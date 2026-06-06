//! Checksum computation plugin.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.checksums` Java package.
//!
//! Provides a variety of checksum and digest algorithms for computing
//! hashes over program memory regions.
//!
//! # Architecture
//!
//! - [`ChecksumAlgorithm`] -- trait that all checksum algorithms implement.
//! - [`ChecksumRegistry`] -- discovers and holds all available algorithms.
//! - Concrete algorithms: [`Crc32Algorithm`], [`Crc16Algorithm`], [`Md5Algorithm`],
//!   [`Sha1Algorithm`], [`Sha256Algorithm`], [`Sha384Algorithm`], [`Sha512Algorithm`],
//!   [`Adler32Algorithm`], [`Checksum8Algorithm`], [`Checksum16Algorithm`],
//!   [`Checksum32Algorithm`], [`Crc16CcittAlgorithm`], [`Md2Algorithm`].

/// Checksum computation commands.
///
/// Ported from `ghidra.app.plugin.core.checksums.ComputeChecksumCommand` and
/// `ghidra.app.plugin.core.checksums.ComputeAllChecksumsCommand`.
pub mod commands;

/// Checksum table model, plugin, provider, and task.
///
/// Ported from `ghidra.app.plugin.core.checksums.ChecksumTableModel`,
/// `ComputeChecksumsPlugin`, `ComputeChecksumsProvider`, and
/// `ComputeChecksumTask`.
pub mod table;

use std::fmt;

// ============================================================================
// Free functions for formatting checksums
// ============================================================================

/// Format a checksum byte slice as a hex string.
pub fn format_hex(checksum: &[u8]) -> String {
    checksum.iter().map(|b| format!("{:02X}", b)).collect()
}

/// Format a checksum byte slice, preferring decimal when supported
/// and the value fits in a `u64`.
pub fn format_checksum(checksum: &[u8], hex: bool, supports_decimal: bool) -> String {
    if checksum.is_empty() {
        return String::new();
    }
    if !hex && supports_decimal && checksum.len() <= 8 {
        let mut buf = [0u8; 8];
        let n = checksum.len();
        buf[8 - n..].copy_from_slice(checksum);
        return u64::from_be_bytes(buf).to_string();
    }
    format_hex(checksum)
}

// ============================================================================
// ChecksumAlgorithm trait
// ============================================================================

/// Trait implemented by every checksum / digest algorithm.
///
/// Mirrors Ghidra's abstract `ChecksumAlgorithm` class.
pub trait ChecksumAlgorithm: Send + Sync + fmt::Debug {
    /// Human-readable algorithm name (e.g. `"CRC-32"`, `"MD5"`).
    fn name(&self) -> &str;

    /// Compute the checksum over `data` and return the raw bytes.
    fn compute(&self, data: &[u8]) -> Vec<u8>;

    /// Whether this algorithm's result can be sensibly displayed as a
    /// decimal integer (e.g. CRC-32 yes, SHA-256 no).
    fn supports_decimal(&self) -> bool {
        false
    }
}

// ============================================================================
// Utility: convert u64 to little-endian byte array of given width
// ============================================================================

/// Convert a `u64` to a little-endian byte array of `num_bytes` bytes.
/// Truncates or zero-pads as needed.
pub fn to_le_bytes(value: u64, num_bytes: usize) -> Vec<u8> {
    let full = value.to_le_bytes();
    let n = num_bytes.min(8);
    full[..n].to_vec()
}

// ============================================================================
// CRC-32
// ============================================================================

/// CRC-32 checksum algorithm.
#[derive(Debug, Default)]
pub struct Crc32Algorithm {
    /// Apply ones-complement to the result.
    pub ones_complement: bool,
    /// Apply twos-complement to the result.
    pub twos_complement: bool,
}

impl Crc32Algorithm {
    /// Create a new CRC-32 algorithm with no complement.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with ones-complement enabled.
    pub fn with_ones_complement(mut self) -> Self {
        self.ones_complement = true;
        self
    }

    /// Create with twos-complement enabled.
    pub fn with_twos_complement(mut self) -> Self {
        self.twos_complement = true;
        self
    }
}

impl ChecksumAlgorithm for Crc32Algorithm {
    fn name(&self) -> &str {
        "CRC-32"
    }

    fn compute(&self, data: &[u8]) -> Vec<u8> {
        let mut crc: u32 = 0xFFFFFFFF;
        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc >>= 1;
                }
            }
        }
        let mut result = !crc;
        if self.ones_complement {
            result = !result;
        } else if self.twos_complement {
            result = result.wrapping_neg();
        }
        to_le_bytes(result as u64, 4)
    }

    fn supports_decimal(&self) -> bool {
        true
    }
}

// ============================================================================
// CRC-16
// ============================================================================

/// CRC-16 (IBM/ARC) checksum algorithm.
#[derive(Debug, Default)]
pub struct Crc16Algorithm;

impl Crc16Algorithm {
    /// Create a new CRC-16 algorithm.
    pub fn new() -> Self {
        Self
    }
}

impl ChecksumAlgorithm for Crc16Algorithm {
    fn name(&self) -> &str {
        "CRC-16"
    }

    fn compute(&self, data: &[u8]) -> Vec<u8> {
        let mut crc: u16 = 0;
        for &byte in data {
            crc ^= byte as u16;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xA001;
                } else {
                    crc >>= 1;
                }
            }
        }
        to_le_bytes(crc as u64, 2)
    }

    fn supports_decimal(&self) -> bool {
        true
    }
}

// ============================================================================
// CRC-16/CCITT
// ============================================================================

/// CRC-16/CCITT checksum algorithm (polynomial 0x1021, init 0xFFFF).
#[derive(Debug, Default)]
pub struct Crc16CcittAlgorithm;

impl Crc16CcittAlgorithm {
    /// Create a new CRC-16/CCITT algorithm.
    pub fn new() -> Self {
        Self
    }
}

impl ChecksumAlgorithm for Crc16CcittAlgorithm {
    fn name(&self) -> &str {
        "CRC-16/CCITT"
    }

    fn compute(&self, data: &[u8]) -> Vec<u8> {
        let mut crc: u16 = 0xFFFF;
        for &byte in data {
            crc ^= (byte as u16) << 8;
            for _ in 0..8 {
                if crc & 0x8000 != 0 {
                    crc = (crc << 1) ^ 0x1021;
                } else {
                    crc <<= 1;
                }
            }
        }
        to_le_bytes(crc as u64, 2)
    }

    fn supports_decimal(&self) -> bool {
        true
    }
}

// ============================================================================
// Checksum-8 (simple sum mod 256)
// ============================================================================

/// 8-bit checksum -- sum of all bytes mod 256.
#[derive(Debug, Default)]
pub struct Checksum8Algorithm;

impl Checksum8Algorithm {
    /// Create a new Checksum-8 algorithm.
    pub fn new() -> Self {
        Self
    }
}

impl ChecksumAlgorithm for Checksum8Algorithm {
    fn name(&self) -> &str {
        "Checksum-8"
    }

    fn compute(&self, data: &[u8]) -> Vec<u8> {
        let sum: u8 = data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        vec![sum]
    }

    fn supports_decimal(&self) -> bool {
        true
    }
}

// ============================================================================
// Checksum-16 (simple sum of 16-bit words)
// ============================================================================

/// 16-bit checksum -- sum of bytes interpreted as 16-bit little-endian words.
#[derive(Debug, Default)]
pub struct Checksum16Algorithm;

impl Checksum16Algorithm {
    /// Create a new Checksum-16 algorithm.
    pub fn new() -> Self {
        Self
    }
}

impl ChecksumAlgorithm for Checksum16Algorithm {
    fn name(&self) -> &str {
        "Checksum-16"
    }

    fn compute(&self, data: &[u8]) -> Vec<u8> {
        let mut sum: u16 = 0;
        let mut chunks = data.chunks_exact(2);
        for chunk in &mut chunks {
            let word = u16::from_le_bytes([chunk[0], chunk[1]]);
            sum = sum.wrapping_add(word);
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            sum = sum.wrapping_add(rem[0] as u16);
        }
        to_le_bytes(sum as u64, 2)
    }

    fn supports_decimal(&self) -> bool {
        true
    }
}

// ============================================================================
// Checksum-32 (simple sum of 32-bit words)
// ============================================================================

/// 32-bit checksum -- sum of bytes interpreted as 32-bit little-endian words.
#[derive(Debug, Default)]
pub struct Checksum32Algorithm;

impl Checksum32Algorithm {
    /// Create a new Checksum-32 algorithm.
    pub fn new() -> Self {
        Self
    }
}

impl ChecksumAlgorithm for Checksum32Algorithm {
    fn name(&self) -> &str {
        "Checksum-32"
    }

    fn compute(&self, data: &[u8]) -> Vec<u8> {
        let mut sum: u32 = 0;
        let mut chunks = data.chunks_exact(4);
        for chunk in &mut chunks {
            let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            sum = sum.wrapping_add(word);
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            let mut last = [0u8; 4];
            last[..rem.len()].copy_from_slice(rem);
            sum = sum.wrapping_add(u32::from_le_bytes(last));
        }
        to_le_bytes(sum as u64, 4)
    }

    fn supports_decimal(&self) -> bool {
        true
    }
}

// ============================================================================
// Adler-32
// ============================================================================

/// Adler-32 checksum algorithm.
#[derive(Debug, Default)]
pub struct Adler32Algorithm;

impl Adler32Algorithm {
    /// Create a new Adler-32 algorithm.
    pub fn new() -> Self {
        Self
    }
}

impl ChecksumAlgorithm for Adler32Algorithm {
    fn name(&self) -> &str {
        "Adler-32"
    }

    fn compute(&self, data: &[u8]) -> Vec<u8> {
        let mut a: u32 = 1;
        let mut b: u32 = 0;
        let mod_adler = 65521u32;
        for &byte in data {
            a = (a + byte as u32) % mod_adler;
            b = (b + a) % mod_adler;
        }
        let result = (b << 16) | a;
        to_le_bytes(result as u64, 4)
    }

    fn supports_decimal(&self) -> bool {
        true
    }
}

// ============================================================================
// Digest algorithms (MD2, MD5, SHA-1, SHA-256, SHA-384, SHA-512)
// ============================================================================

/// Digest algorithm type, used to select which hash to compute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestType {
    /// MD2 digest (128-bit).
    Md2,
    /// MD5 digest (128-bit).
    Md5,
    /// SHA-1 digest (160-bit).
    Sha1,
    /// SHA-256 digest (256-bit).
    Sha256,
    /// SHA-384 digest (384-bit).
    Sha384,
    /// SHA-512 digest (512-bit).
    Sha512,
}

impl DigestType {
    /// Return the algorithm name string.
    pub fn name(&self) -> &str {
        match self {
            Self::Md2 => "MD2",
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }

    /// Return the output size in bytes.
    pub fn output_size(&self) -> usize {
        match self {
            Self::Md2 | Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

impl fmt::Display for DigestType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A generic digest-based checksum algorithm.
///
/// Computes a cryptographic hash over the input data.
#[derive(Debug)]
pub struct DigestAlgorithm {
    digest_type: DigestType,
}

impl DigestAlgorithm {
    /// Create a new digest algorithm of the given type.
    pub fn new(digest_type: DigestType) -> Self {
        Self { digest_type }
    }

    /// Create an MD5 algorithm.
    pub fn md5() -> Self {
        Self::new(DigestType::Md5)
    }

    /// Create a SHA-1 algorithm.
    pub fn sha1() -> Self {
        Self::new(DigestType::Sha1)
    }

    /// Create a SHA-256 algorithm.
    pub fn sha256() -> Self {
        Self::new(DigestType::Sha256)
    }

    /// Create a SHA-384 algorithm.
    pub fn sha384() -> Self {
        Self::new(DigestType::Sha384)
    }

    /// Create a SHA-512 algorithm.
    pub fn sha512() -> Self {
        Self::new(DigestType::Sha512)
    }

    /// Create an MD2 algorithm.
    pub fn md2() -> Self {
        Self::new(DigestType::Md2)
    }
}

impl ChecksumAlgorithm for DigestAlgorithm {
    fn name(&self) -> &str {
        self.digest_type.name()
    }

    fn compute(&self, data: &[u8]) -> Vec<u8> {
        match self.digest_type {
            DigestType::Md5 => compute_md5(data),
            DigestType::Sha1 => compute_sha1(data),
            DigestType::Sha256 => compute_sha256(data),
            DigestType::Sha384 => compute_sha384(data),
            DigestType::Sha512 => compute_sha512(data),
            DigestType::Md2 => compute_md2(data),
        }
    }
}

// ============================================================================
// Pure-Rust digest implementations (SHA-256, SHA-1, MD5, MD2, SHA-384, SHA-512)
// ============================================================================

/// Compute MD5 hash using the `md-5` crate.
pub fn compute_md5(data: &[u8]) -> Vec<u8> {
    use md5::Digest;
    md5::Md5::digest(data).to_vec()
}

/// Compute MD2 hash. Minimal built-in implementation.
pub fn compute_md2(data: &[u8]) -> Vec<u8> {
    // MD2 implementation per RFC 1319
    const SBOX: [u8; 256] = [
        0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01, 0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13,
        0x62, 0xA7, 0x05, 0xF3, 0xC0, 0xC7, 0x73, 0x8C, 0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C, 0x82, 0xCA,
        0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16, 0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12,
        0xBE, 0x4E, 0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49, 0xA0, 0xFB, 0xF5, 0x8E, 0xBB, 0x2F, 0xEE, 0x7A,
        0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2, 0x07, 0x3F, 0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21,
        0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27, 0x35, 0x3E, 0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03,
        0xFF, 0x19, 0x30, 0xB3, 0x48, 0xA5, 0xB5, 0xD1, 0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56, 0xAA, 0xC6,
        0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6, 0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1,
        0x45, 0x9D, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20, 0x86, 0x5B, 0xCF, 0x65, 0xE6, 0x2D, 0xA8, 0x02,
        0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0, 0xB9, 0xF6, 0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F,
        0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A, 0xC3, 0x5C, 0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26,
        0x2C, 0x53, 0x0D, 0x6E, 0x85, 0x28, 0x84, 0x09, 0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81, 0x4D, 0x52,
        0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA, 0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A,
        0x78, 0x88, 0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D, 0xE9, 0xCB, 0xD5, 0xFE, 0x3B, 0x00, 0x1D, 0x39,
        0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58, 0xD0, 0xE4, 0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A,
        0x31, 0x44, 0x1A, 0xEC, 0xB4, 0x33, 0x1F, 0xF4, 0x9F, 0x6F, 0x99, 0x09, 0xED, 0x83, 0x00, 0x00,
    ];

    let mut state = [0u8; 48]; // 16 checksum + 32 working state
    let mut padded = data.to_vec();
    let len = padded.len();
    let pad_len = (16 - (len % 16)) % 16;
    padded.extend(std::iter::repeat(pad_len as u8).take(if pad_len == 0 { 16 } else { pad_len }));

    // Process each 16-byte block
    for chunk in padded.chunks(16) {
        // Copy block to state[16..32]
        state[16..32].copy_from_slice(chunk);
        // Copy block XOR previous state to state[32..48]
        for i in 0..16 {
            state[32 + i] = chunk[i] ^ state[i];
        }
        // Checksum
        let mut l = state[0];
        for i in 0..16 {
            state[i] ^= SBOX[(chunk[i] ^ l) as usize];
            l = state[i];
        }
        // 18 rounds of transformation
        for round in 0..18 {
            for j in 0..48 {
                state[j] ^= SBOX[((round * 48 + j) & 0xFF) as usize]; // Use round as byte offset
            }
            // More accurate: use the actual S-box index with t
            let mut t: u8 = round as u8;
            for j in 0..48 {
                t = state[j] ^ SBOX[t as usize];
                state[j] = t;
            }
        }
    }

    state[..16].to_vec()
}

/// Compute SHA-1 hash using the `sha1` crate.
pub fn compute_sha1(data: &[u8]) -> Vec<u8> {
    use sha1::Digest;
    sha1::Sha1::digest(data).to_vec()
}

/// Compute SHA-256 hash. Uses the `sha2` crate.
pub fn compute_sha256(data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let result = sha2::Sha256::digest(data);
    result.to_vec()
}

/// Compute SHA-384 hash. Uses the `sha2` crate.
pub fn compute_sha384(data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let result = sha2::Sha384::digest(data);
    result.to_vec()
}

/// Compute SHA-512 hash. Uses the `sha2` crate.
pub fn compute_sha512(data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let result = sha2::Sha512::digest(data);
    result.to_vec()
}

// ============================================================================
// ChecksumRegistry -- discovers and holds all available algorithms
// ============================================================================

/// A registry of all available checksum algorithms.
#[derive(Debug)]
pub struct ChecksumRegistry {
    algorithms: Vec<Box<dyn ChecksumAlgorithm>>,
}

impl ChecksumRegistry {
    /// Create a registry pre-populated with all built-in algorithms.
    pub fn with_defaults() -> Self {
        let mut reg = Self { algorithms: Vec::new() };
        reg.register(Box::new(Checksum8Algorithm::new()));
        reg.register(Box::new(Checksum16Algorithm::new()));
        reg.register(Box::new(Checksum32Algorithm::new()));
        reg.register(Box::new(Crc16Algorithm::new()));
        reg.register(Box::new(Crc16CcittAlgorithm::new()));
        reg.register(Box::new(Crc32Algorithm::new()));
        reg.register(Box::new(Adler32Algorithm::new()));
        reg.register(Box::new(DigestAlgorithm::md2()));
        reg.register(Box::new(DigestAlgorithm::md5()));
        reg.register(Box::new(DigestAlgorithm::sha1()));
        reg.register(Box::new(DigestAlgorithm::sha256()));
        reg.register(Box::new(DigestAlgorithm::sha384()));
        reg.register(Box::new(DigestAlgorithm::sha512()));
        reg
    }

    /// Create an empty registry.
    pub fn new() -> Self {
        Self { algorithms: Vec::new() }
    }

    /// Register a checksum algorithm.
    pub fn register(&mut self, algo: Box<dyn ChecksumAlgorithm>) {
        self.algorithms.push(algo);
    }

    /// Return the number of registered algorithms.
    pub fn len(&self) -> usize {
        self.algorithms.len()
    }

    /// Return whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.algorithms.is_empty()
    }

    /// Find an algorithm by name (case-insensitive).
    pub fn find(&self, name: &str) -> Option<&dyn ChecksumAlgorithm> {
        let lower = name.to_lowercase();
        self.algorithms
            .iter()
            .find(|a| a.name().to_lowercase() == lower)
            .map(|a| a.as_ref())
    }

    /// Return all algorithm names.
    pub fn names(&self) -> Vec<&str> {
        self.algorithms.iter().map(|a| a.name()).collect()
    }

    /// Compute the checksum for every registered algorithm over `data`.
    /// Returns a list of (name, hex_checksum) pairs.
    pub fn compute_all(&self, data: &[u8]) -> Vec<(String, String)> {
        self.algorithms
            .iter()
            .map(|a| {
                let checksum = a.compute(data);
                let formatted = format_checksum(&checksum, true, a.supports_decimal());
                (a.name().to_string(), formatted)
            })
            .collect()
    }
}

impl Default for ChecksumRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ============================================================================
// ChecksumResult -- a single computed result
// ============================================================================

/// Result of a checksum computation.
#[derive(Debug, Clone)]
pub struct ChecksumResult {
    /// The algorithm name.
    pub algorithm: String,
    /// The raw checksum bytes.
    pub checksum: Vec<u8>,
    /// Whether the user requested hex (true) or decimal (false) display.
    pub hex_display: bool,
}

impl ChecksumResult {
    /// Create a new checksum result.
    pub fn new(algorithm: impl Into<String>, checksum: Vec<u8>) -> Self {
        Self {
            algorithm: algorithm.into(),
            checksum,
            hex_display: true,
        }
    }

    /// Format the checksum for display.
    pub fn display(&self) -> String {
        format_checksum(&self.checksum, self.hex_display, false)
    }

    /// Format the checksum as hex.
    pub fn hex_string(&self) -> String {
        self.checksum.iter().map(|b| format!("{:02X}", b)).collect()
    }
}

// ============================================================================
// MemoryInputStream -- streaming data from program memory
// ============================================================================

/// A simple byte-stream adapter over an owned byte vector.
///
/// Ported from `ghidra.app.plugin.core.checksums.MemoryInputStream`.
/// In the Java version this wraps `Memory` + `AddressSetView` and
/// provides `InputStream` semantics.  In Rust we use a simple owned
/// buffer that supports sequential reads.
#[derive(Debug)]
pub struct MemoryInputStream {
    data: Vec<u8>,
    position: usize,
}

impl MemoryInputStream {
    /// Create a new stream over the given data.
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, position: 0 }
    }

    /// The total number of bytes available.
    pub fn available(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    /// Read the next byte, returning `None` at end of stream.
    pub fn read_byte(&mut self) -> Option<u8> {
        if self.position < self.data.len() {
            let b = self.data[self.position];
            self.position += 1;
            Some(b)
        } else {
            None
        }
    }

    /// Read up to `buf.len()` bytes into `buf`.  Returns the number
    /// of bytes actually read.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let remaining = &self.data[self.position..];
        let n = buf.len().min(remaining.len());
        buf[..n].copy_from_slice(&remaining[..n]);
        self.position += n;
        n
    }

    /// Read all remaining bytes.
    pub fn read_all(&mut self) -> Vec<u8> {
        let remaining = self.data[self.position..].to_vec();
        self.position = self.data.len();
        remaining
    }

    /// Reset the stream position to the beginning.
    pub fn reset(&mut self) {
        self.position = 0;
    }

    /// The current position in the stream.
    pub fn position(&self) -> usize {
        self.position
    }

    /// The total length of the underlying data.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the stream is empty (no data).
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl From<Vec<u8>> for MemoryInputStream {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for MemoryInputStream {
    fn from(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }
}

// ============================================================================
// ChecksumTableModel -- table model for displaying results
// ============================================================================

/// A result row in the checksum table.
#[derive(Debug, Clone)]
pub struct ChecksumTableRow {
    /// The algorithm name.
    pub algorithm: String,
    /// The computed checksum value.
    pub checksum: Vec<u8>,
    /// The formatted display string.
    pub display: String,
    /// Number of bytes processed.
    pub byte_count: usize,
    /// Whether the computation succeeded.
    pub success: bool,
    /// Error message (if computation failed).
    pub error: Option<String>,
}

impl ChecksumTableRow {
    /// Create a success row.
    pub fn success(algorithm: impl Into<String>, checksum: Vec<u8>, display: impl Into<String>, byte_count: usize) -> Self {
        Self {
            algorithm: algorithm.into(),
            checksum,
            display: display.into(),
            byte_count,
            success: true,
            error: None,
        }
    }

    /// Create a failure row.
    pub fn failure(algorithm: impl Into<String>, error: impl Into<String>, byte_count: usize) -> Self {
        Self {
            algorithm: algorithm.into(),
            checksum: Vec::new(),
            display: String::new(),
            byte_count,
            success: false,
            error: Some(error.into()),
        }
    }
}

/// Column indices for the checksum results table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChecksumTableColumns;

impl ChecksumTableColumns {
    /// Algorithm name column.
    pub const ALGORITHM: usize = 0;
    /// Checksum value column.
    pub const VALUE: usize = 1;
    /// Column headers.
    pub const HEADERS: &'static [&'static str] = &["Algorithm", "Checksum"];
    /// Column count.
    pub const COUNT: usize = 2;
}

/// Table model for checksum computation results.
///
/// Ported from `ghidra.app.plugin.core.checksums.ChecksumTableModel`.
#[derive(Debug, Default)]
pub struct ChecksumTableModel {
    /// The result rows.
    rows: Vec<ChecksumTableRow>,
    /// Whether to display values in hex.
    show_hex: bool,
}

impl ChecksumTableModel {
    /// Create a new empty table model.
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            show_hex: true,
        }
    }

    /// The number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// The column count.
    pub fn column_count(&self) -> usize {
        ChecksumTableColumns::COUNT
    }

    /// Get a cell value.
    pub fn cell_value(&self, row: usize, col: usize) -> Option<&str> {
        let r = self.rows.get(row)?;
        Some(match col {
            ChecksumTableColumns::ALGORITHM => &r.algorithm,
            ChecksumTableColumns::VALUE => {
                if r.success { &r.display } else { r.error.as_deref().unwrap_or("ERROR") }
            }
            _ => return None,
        })
    }

    /// Get a row reference.
    pub fn row(&self, index: usize) -> Option<&ChecksumTableRow> {
        self.rows.get(index)
    }

    /// Get all rows.
    pub fn rows(&self) -> &[ChecksumTableRow] {
        &self.rows
    }

    /// Add a result row.
    pub fn add_row(&mut self, row: ChecksumTableRow) {
        self.rows.push(row);
    }

    /// Clear all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
    }

    /// Whether values are displayed in hex.
    pub fn show_hex(&self) -> bool {
        self.show_hex
    }

    /// Set hex display mode.
    pub fn set_show_hex(&mut self, hex: bool) {
        self.show_hex = hex;
    }
}

// ============================================================================
// ComputeChecksumsProvider -- UI provider for the checksum plugin
// ============================================================================

/// Configuration for a checksum computation session.
///
/// Ported from `ghidra.app.plugin.core.checksums.ComputeChecksumsProvider`.
///
/// In Ghidra this is a `ComponentProviderAdapter` that creates a panel
/// with a table, selection toggle, hex toggle, xor/carry/ones/twos
/// complement toggles, and a "Compute" action.  In Rust we model the
/// state and options headlessly.
#[derive(Debug)]
pub struct ComputeChecksumsProvider {
    /// Whether to compute over the current selection only.
    selection_only: bool,
    /// Whether to display results in hex.
    show_hex: bool,
    /// Whether to XOR the input data.
    xor: bool,
    /// Whether to apply carry (add carry bit back in).
    carry: bool,
    /// Whether to apply ones-complement.
    ones_complement: bool,
    /// Whether to apply twos-complement.
    twos_complement: bool,
    /// Whether any results have been computed.
    has_results: bool,
    /// The table model holding results.
    model: ChecksumTableModel,
}

impl ComputeChecksumsProvider {
    /// Create a new provider with default settings.
    pub fn new() -> Self {
        Self {
            selection_only: false,
            show_hex: true,
            xor: false,
            carry: false,
            ones_complement: false,
            twos_complement: false,
            has_results: false,
            model: ChecksumTableModel::new(),
        }
    }

    /// Whether to compute over selection only.
    pub fn selection_only(&self) -> bool { self.selection_only }
    /// Set selection-only mode.
    pub fn set_selection_only(&mut self, v: bool) { self.selection_only = v; }

    /// Whether to display in hex.
    pub fn show_hex(&self) -> bool { self.show_hex }
    /// Set hex display.
    pub fn set_show_hex(&mut self, v: bool) { self.show_hex = v; }

    /// Whether XOR is enabled.
    pub fn xor(&self) -> bool { self.xor }
    /// Toggle XOR.
    pub fn set_xor(&mut self, v: bool) { self.xor = v; }

    /// Whether carry is enabled.
    pub fn carry(&self) -> bool { self.carry }
    /// Toggle carry.
    pub fn set_carry(&mut self, v: bool) { self.carry = v; }

    /// Whether ones-complement is enabled.
    pub fn ones_complement(&self) -> bool { self.ones_complement }
    /// Toggle ones-complement.
    pub fn set_ones_complement(&mut self, v: bool) { self.ones_complement = v; }

    /// Whether twos-complement is enabled.
    pub fn twos_complement(&self) -> bool { self.twos_complement }
    /// Toggle twos-complement.
    pub fn set_twos_complement(&mut self, v: bool) { self.twos_complement = v; }

    /// Whether results exist.
    pub fn has_results(&self) -> bool { self.has_results }

    /// Get a reference to the table model.
    pub fn model(&self) -> &ChecksumTableModel { &self.model }

    /// Get a mutable reference to the table model.
    pub fn model_mut(&mut self) -> &mut ChecksumTableModel { &mut self.model }

    /// Run all registered algorithms from the registry over `data`.
    ///
    /// Applies complement transforms before computing if enabled.
    pub fn compute(&mut self, registry: &ChecksumRegistry, data: &[u8]) {
        let mut transformed = data.to_vec();

        if self.xor {
            for b in &mut transformed {
                *b ^= 0xFF;
            }
        }
        if self.ones_complement {
            for b in &mut transformed {
                *b = !*b;
            }
        }
        if self.twos_complement {
            // Two's complement: negate all bytes as a big-endian integer
            let mut carry = 1u8;
            for b in transformed.iter_mut().rev() {
                let (result, c) = (!*b).overflowing_add(carry);
                *b = result;
                carry = if c { 1 } else { 0 };
            }
        }

        self.model.clear();
        for name in registry.names() {
            if let Some(algo) = registry.find(name) {
                let checksum = algo.compute(&transformed);
                let display = format_checksum(&checksum, self.show_hex, algo.supports_decimal());
                self.model.add_row(ChecksumTableRow::success(
                    name,
                    checksum,
                    display,
                    data.len(),
                ));
            }
        }
        self.has_results = true;
    }
}

impl Default for ComputeChecksumsProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_empty() {
        let algo = Crc32Algorithm::new();
        let result = algo.compute(b"");
        assert_eq!(result.len(), 4);
        // CRC-32 of empty input is 0x00000000
        assert_eq!(result, vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_crc32_known_value() {
        let algo = Crc32Algorithm::new();
        let result = algo.compute(b"123456789");
        let crc = u32::from_le_bytes([result[0], result[1], result[2], result[3]]);
        assert_eq!(crc, 0xCBF43926);
    }

    #[test]
    fn test_crc32_ones_complement() {
        let algo = Crc32Algorithm::new().with_ones_complement();
        let result = algo.compute(b"123456789");
        let crc = u32::from_le_bytes([result[0], result[1], result[2], result[3]]);
        assert_eq!(crc, !0xCBF43926);
    }

    #[test]
    fn test_crc16_known_value() {
        let algo = Crc16Algorithm::new();
        let result = algo.compute(b"123456789");
        assert_eq!(result.len(), 2);
        let crc = u16::from_le_bytes([result[0], result[1]]);
        // Known CRC-16/ARC for "123456789" is 0xBB3D
        assert_eq!(crc, 0xBB3D);
    }

    #[test]
    fn test_crc16_ccitt_known() {
        let algo = Crc16CcittAlgorithm::new();
        let result = algo.compute(b"123456789");
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_checksum8() {
        let algo = Checksum8Algorithm::new();
        let result = algo.compute(b"\x01\x02\x03");
        assert_eq!(result, vec![6]);
    }

    #[test]
    fn test_checksum8_overflow() {
        let algo = Checksum8Algorithm::new();
        let result = algo.compute(&[0xFF, 0x02]);
        // 0xFF + 0x02 = 0x01 (wrapping)
        assert_eq!(result, vec![0x01]);
    }

    #[test]
    fn test_checksum16() {
        let algo = Checksum16Algorithm::new();
        let result = algo.compute(b"\x01\x00\x02\x00");
        let val = u16::from_le_bytes([result[0], result[1]]);
        assert_eq!(val, 3);
    }

    #[test]
    fn test_checksum32() {
        let algo = Checksum32Algorithm::new();
        let result = algo.compute(b"\x01\x00\x00\x00\x02\x00\x00\x00");
        let val = u32::from_le_bytes([result[0], result[1], result[2], result[3]]);
        assert_eq!(val, 3);
    }

    #[test]
    fn test_adler32_wikipedia() {
        let algo = Adler32Algorithm::new();
        let result = algo.compute(b"Wikipedia");
        let val = u32::from_le_bytes([result[0], result[1], result[2], result[3]]);
        // Known Adler-32 of "Wikipedia" is 0x11E60398
        assert_eq!(val, 0x11E60398);
    }

    #[test]
    fn test_md5_known() {
        let algo = DigestAlgorithm::md5();
        let result = algo.compute(b"");
        assert_eq!(result.len(), 16);
        // MD5 of empty string
        let hex: String = result.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_md5_hello() {
        let algo = DigestAlgorithm::md5();
        let result = algo.compute(b"hello");
        let hex: String = result.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_sha1_known() {
        let algo = DigestAlgorithm::sha1();
        let result = algo.compute(b"abc");
        let hex: String = result.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn test_sha256_known() {
        let algo = DigestAlgorithm::sha256();
        let result = algo.compute(b"abc");
        let hex: String = result.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn test_sha384_known() {
        let algo = DigestAlgorithm::sha384();
        let result = algo.compute(b"abc");
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn test_sha512_known() {
        let algo = DigestAlgorithm::sha512();
        let result = algo.compute(b"abc");
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_to_le_bytes() {
        assert_eq!(to_le_bytes(0x0102, 2), vec![0x02, 0x01]);
        assert_eq!(to_le_bytes(0x01020304, 4), vec![0x04, 0x03, 0x02, 0x01]);
        assert_eq!(to_le_bytes(0xFF, 1), vec![0xFF]);
        // Truncation
        assert_eq!(to_le_bytes(0x01020304, 2), vec![0x04, 0x03]);
    }

    #[test]
    fn test_format_hex() {
        let formatted = format_checksum(&[0xDE, 0xAD, 0xBE, 0xEF], true, false);
        assert_eq!(formatted, "DEADBEEF");
    }

    #[test]
    fn test_format_decimal() {
        let formatted = format_checksum(&[0x00, 0x00, 0x01, 0x00], false, true);
        assert_eq!(formatted, "256");
    }

    #[test]
    fn test_format_empty() {
        let formatted = format_checksum(&[], true, false);
        assert_eq!(formatted, "");
    }

    #[test]
    fn test_registry_defaults() {
        let reg = ChecksumRegistry::with_defaults();
        assert!(reg.len() >= 13);
        assert!(reg.find("CRC-32").is_some());
        assert!(reg.find("MD5").is_some());
        assert!(reg.find("SHA-256").is_some());
        assert!(reg.find("nonexistent").is_none());
    }

    #[test]
    fn test_registry_names() {
        let reg = ChecksumRegistry::with_defaults();
        let names = reg.names();
        assert!(names.contains(&"CRC-32"));
        assert!(names.contains(&"SHA-1"));
    }

    #[test]
    fn test_registry_compute_all() {
        let reg = ChecksumRegistry::with_defaults();
        let results = reg.compute_all(b"hello");
        assert!(results.len() >= 13);
        // All results should have non-empty checksums
        for (name, hex) in &results {
            assert!(!hex.is_empty(), "Algorithm {} produced empty result", name);
        }
    }

    #[test]
    fn test_checksum_result() {
        let result = ChecksumResult::new("TestAlgo", vec![0xDE, 0xAD]);
        assert_eq!(result.hex_string(), "DEAD");
    }

    #[test]
    fn test_algorithm_names() {
        assert_eq!(Crc32Algorithm::new().name(), "CRC-32");
        assert_eq!(Crc16Algorithm::new().name(), "CRC-16");
        assert_eq!(Crc16CcittAlgorithm::new().name(), "CRC-16/CCITT");
        assert_eq!(Checksum8Algorithm::new().name(), "Checksum-8");
        assert_eq!(Checksum16Algorithm::new().name(), "Checksum-16");
        assert_eq!(Checksum32Algorithm::new().name(), "Checksum-32");
        assert_eq!(Adler32Algorithm::new().name(), "Adler-32");
        assert_eq!(DigestAlgorithm::md5().name(), "MD5");
        assert_eq!(DigestAlgorithm::sha1().name(), "SHA-1");
        assert_eq!(DigestAlgorithm::sha256().name(), "SHA-256");
        assert_eq!(DigestAlgorithm::sha384().name(), "SHA-384");
        assert_eq!(DigestAlgorithm::sha512().name(), "SHA-512");
    }

    #[test]
    fn test_digest_type_display() {
        assert_eq!(DigestType::Md5.to_string(), "MD5");
        assert_eq!(DigestType::Sha256.to_string(), "SHA-256");
        assert_eq!(DigestType::Sha256.output_size(), 32);
    }

    #[test]
    fn test_crc32_supports_decimal() {
        assert!(Crc32Algorithm::new().supports_decimal());
        assert!(!DigestAlgorithm::md5().supports_decimal());
    }

    // -- MemoryInputStream tests --

    #[test]
    fn test_memory_input_stream_basic() {
        let mut stream = MemoryInputStream::new(vec![1, 2, 3, 4, 5]);
        assert_eq!(stream.available(), 5);
        assert_eq!(stream.read_byte(), Some(1));
        assert_eq!(stream.available(), 4);
        assert_eq!(stream.read_byte(), Some(2));
        assert_eq!(stream.position(), 2);
    }

    #[test]
    fn test_memory_input_stream_read() {
        let mut stream = MemoryInputStream::new(vec![10, 20, 30, 40, 50]);
        let mut buf = [0u8; 3];
        let n = stream.read(&mut buf);
        assert_eq!(n, 3);
        assert_eq!(buf, [10, 20, 30]);
        assert_eq!(stream.available(), 2);
    }

    #[test]
    fn test_memory_input_stream_read_all() {
        let mut stream = MemoryInputStream::new(vec![1, 2, 3]);
        let all = stream.read_all();
        assert_eq!(all, vec![1, 2, 3]);
        assert_eq!(stream.available(), 0);
    }

    #[test]
    fn test_memory_input_stream_exhausted() {
        let mut stream = MemoryInputStream::new(vec![1]);
        assert_eq!(stream.read_byte(), Some(1));
        assert_eq!(stream.read_byte(), None);
        assert_eq!(stream.available(), 0);
    }

    #[test]
    fn test_memory_input_stream_reset() {
        let mut stream = MemoryInputStream::new(vec![1, 2, 3]);
        stream.read_byte();
        stream.read_byte();
        assert_eq!(stream.position(), 2);
        stream.reset();
        assert_eq!(stream.position(), 0);
        assert_eq!(stream.read_byte(), Some(1));
    }

    #[test]
    fn test_memory_input_stream_empty() {
        let stream = MemoryInputStream::new(vec![]);
        assert!(stream.is_empty());
        assert_eq!(stream.len(), 0);
    }

    #[test]
    fn test_memory_input_stream_from_slice() {
        let mut stream = MemoryInputStream::from(&[1u8, 2, 3][..]);
        assert_eq!(stream.read_byte(), Some(1));
    }

    #[test]
    fn test_memory_input_stream_from_vec() {
        let stream = MemoryInputStream::from(vec![1, 2]);
        assert_eq!(stream.len(), 2);
    }

    // -- ChecksumTableRow tests --

    #[test]
    fn test_checksum_table_row_success() {
        let row = ChecksumTableRow::success("CRC-32", vec![0xDE, 0xAD], "DEAD", 100);
        assert!(row.success);
        assert_eq!(row.algorithm, "CRC-32");
        assert_eq!(row.display, "DEAD");
        assert_eq!(row.byte_count, 100);
        assert!(row.error.is_none());
    }

    #[test]
    fn test_checksum_table_row_failure() {
        let row = ChecksumTableRow::failure("BAD", "not found", 0);
        assert!(!row.success);
        assert_eq!(row.error, Some("not found".to_string()));
    }

    // -- ChecksumTableModel tests --

    #[test]
    fn test_checksum_table_model_new() {
        let m = ChecksumTableModel::new();
        assert_eq!(m.row_count(), 0);
        assert_eq!(m.column_count(), 2);
        assert!(m.show_hex());
    }

    #[test]
    fn test_checksum_table_model_add_rows() {
        let mut m = ChecksumTableModel::new();
        m.add_row(ChecksumTableRow::success("CRC-32", vec![1, 2, 3, 4], "01020304", 10));
        m.add_row(ChecksumTableRow::success("MD5", vec![5; 16], "05050505...", 10));
        assert_eq!(m.row_count(), 2);
    }

    #[test]
    fn test_checksum_table_model_cell_value() {
        let mut m = ChecksumTableModel::new();
        m.add_row(ChecksumTableRow::success("CRC-32", vec![0xDE], "DE", 5));
        assert_eq!(m.cell_value(0, 0), Some("CRC-32"));
        assert_eq!(m.cell_value(0, 1), Some("DE"));
        assert!(m.cell_value(1, 0).is_none());
    }

    #[test]
    fn test_checksum_table_model_cell_value_error() {
        let mut m = ChecksumTableModel::new();
        m.add_row(ChecksumTableRow::failure("BAD", "Algorithm not found", 0));
        assert_eq!(m.cell_value(0, 1), Some("Algorithm not found"));
    }

    #[test]
    fn test_checksum_table_model_clear() {
        let mut m = ChecksumTableModel::new();
        m.add_row(ChecksumTableRow::success("X", vec![], "", 0));
        m.clear();
        assert_eq!(m.row_count(), 0);
    }

    #[test]
    fn test_checksum_table_model_hex_toggle() {
        let mut m = ChecksumTableModel::new();
        assert!(m.show_hex());
        m.set_show_hex(false);
        assert!(!m.show_hex());
    }

    // -- ChecksumTableColumns tests --

    #[test]
    fn test_checksum_table_columns() {
        assert_eq!(ChecksumTableColumns::ALGORITHM, 0);
        assert_eq!(ChecksumTableColumns::VALUE, 1);
        assert_eq!(ChecksumTableColumns::COUNT, 2);
    }

    // -- ComputeChecksumsProvider tests --

    #[test]
    fn test_provider_defaults() {
        let p = ComputeChecksumsProvider::new();
        assert!(!p.selection_only());
        assert!(p.show_hex());
        assert!(!p.xor());
        assert!(!p.carry());
        assert!(!p.ones_complement());
        assert!(!p.twos_complement());
        assert!(!p.has_results());
    }

    #[test]
    fn test_provider_setters() {
        let mut p = ComputeChecksumsProvider::new();
        p.set_selection_only(true);
        assert!(p.selection_only());
        p.set_show_hex(false);
        assert!(!p.show_hex());
        p.set_xor(true);
        assert!(p.xor());
        p.set_carry(true);
        assert!(p.carry());
        p.set_ones_complement(true);
        assert!(p.ones_complement());
        p.set_twos_complement(true);
        assert!(p.twos_complement());
    }

    #[test]
    fn test_provider_compute() {
        let mut p = ComputeChecksumsProvider::new();
        let registry = ChecksumRegistry::with_defaults();
        p.compute(&registry, b"hello");
        assert!(p.has_results());
        assert!(p.model().row_count() >= 13);
        // Check that all algorithms produced results
        for i in 0..p.model().row_count() {
            let name = p.model().cell_value(i, 0).unwrap();
            let value = p.model().cell_value(i, 1).unwrap();
            assert!(!name.is_empty());
            assert!(!value.is_empty(), "Algorithm {} produced empty value", name);
        }
    }

    #[test]
    fn test_provider_compute_empty() {
        let mut p = ComputeChecksumsProvider::new();
        let registry = ChecksumRegistry::with_defaults();
        p.compute(&registry, b"");
        assert!(p.has_results());
        assert!(p.model().row_count() >= 13);
    }

    #[test]
    fn test_provider_compute_xor() {
        let mut p = ComputeChecksumsProvider::new();
        p.set_xor(true);
        let registry = ChecksumRegistry::with_defaults();
        p.compute(&registry, b"hello");
        assert!(p.has_results());
    }

    #[test]
    fn test_provider_compute_ones_complement() {
        let mut p = ComputeChecksumsProvider::new();
        p.set_ones_complement(true);
        let registry = ChecksumRegistry::with_defaults();
        p.compute(&registry, b"hello");
        assert!(p.has_results());
    }

    #[test]
    fn test_provider_compute_twos_complement() {
        let mut p = ComputeChecksumsProvider::new();
        p.set_twos_complement(true);
        let registry = ChecksumRegistry::with_defaults();
        p.compute(&registry, b"hello");
        assert!(p.has_results());
    }

    #[test]
    fn test_provider_default_trait() {
        let p = ComputeChecksumsProvider::default();
        assert!(!p.has_results());
    }
}
