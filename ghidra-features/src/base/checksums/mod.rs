//! Checksum computation algorithms.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.checksums` package.
//!
//! Provides a trait-based framework for computing checksums over byte data,
//! with concrete implementations for:
//!
//! - **Basic checksums**: 8-bit, 16-bit, 32-bit with optional XOR, carry,
//!   ones-complement, and two's-complement.
//! - **CRC checksums**: CRC-16, CRC-16/CCITT, CRC-32.
//! - **Adler-32**: Fast error-detection checksum.
//! - **Message digests**: MD5, SHA-1, SHA-256, SHA-384, SHA-512.
//!
//! # Usage
//!
//! ```rust
//! use ghidra_features::base::checksums::*;
//!
//! let data = b"Hello, World!";
//!
//! // CRC-32
//! let crc = Crc32Algorithm::new();
//! let result = crc.compute(data, &ChecksumOptions::default());
//! assert!(!result.is_empty());
//!
//! // MD5
//! let md5 = DigestChecksum::md5();
//! let result = md5.compute(data, &ChecksumOptions::default());
//! assert_eq!(result.len(), 16);
//!
//! // Basic 32-bit checksum
//! let basic = BasicChecksum::new(ChecksumBitSize::Bits32);
//! let result = basic.compute(data, &ChecksumOptions::default());
//! assert_eq!(result.len(), 4);
//! ```

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// Options that control checksum computation behavior.
///
/// Corresponds to the options available in Ghidra's ComputeChecksumsProvider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChecksumOptions {
    /// If true, accumulate using XOR instead of addition (basic checksums only).
    pub xor: bool,
    /// If true, fold carries back into the result (basic checksums only).
    pub carry: bool,
    /// If true, apply one's complement to the final result.
    pub ones_complement: bool,
    /// If true, apply two's complement to the final result.
    twos_complement: bool,
}

impl Default for ChecksumOptions {
    fn default() -> Self {
        Self {
            xor: false,
            carry: false,
            ones_complement: false,
            twos_complement: false,
        }
    }
}

impl ChecksumOptions {
    /// Create options with two's complement enabled.
    pub fn with_twos_complement() -> Self {
        Self {
            twos_complement: true,
            ..Default::default()
        }
    }

    /// Whether two's complement is set.
    pub fn is_twos_complement(&self) -> bool {
        self.twos_complement
    }
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Trait for checksum algorithm implementations.
///
/// Each implementation computes a checksum over arbitrary byte data.
/// This corresponds to Ghidra's `ChecksumAlgorithm` abstract class.
pub trait ChecksumAlgorithm: Send + Sync {
    /// Human-readable name of the algorithm (e.g., "CRC-32", "MD5").
    fn name(&self) -> &str;

    /// Compute the checksum over the given byte data.
    ///
    /// Returns the checksum as a byte vector. The length depends on the
    /// algorithm (4 bytes for CRC-32, 16 for MD5, etc.).
    fn compute(&self, data: &[u8], options: &ChecksumOptions) -> Vec<u8>;

    /// Whether the result supports decimal display.
    fn supports_decimal(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a 64-bit value to a little-endian byte array of the specified size.
///
/// Ported from `ChecksumAlgorithm.toArray()`.
pub fn to_le_bytes(value: u64, num_bytes: usize) -> Vec<u8> {
    let le = value.to_le_bytes();
    let n = std::cmp::min(8, num_bytes);
    let mut result = vec![0u8; num_bytes];
    result[..n].copy_from_slice(&le[..n]);
    result
}

/// Format a checksum byte slice as a hex string.
pub fn format_hex(checksum: &[u8]) -> String {
    checksum.iter().map(|b| format!("{:02X}", b)).collect()
}

/// Format a checksum byte slice as a decimal string (if it fits in 8 bytes).
pub fn format_decimal(checksum: &[u8]) -> String {
    if checksum.is_empty() {
        return String::new();
    }
    if checksum.len() <= 8 {
        let mut buf = [0u8; 8];
        buf[..checksum.len()].copy_from_slice(checksum);
        let value = u64::from_le_bytes(buf);
        return value.to_string();
    }
    format_hex(checksum)
}

// ---------------------------------------------------------------------------
// Basic Checksum
// ---------------------------------------------------------------------------

/// Supported byte widths for basic checksums.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumBitSize {
    /// 8-bit checksum.
    Bits8,
    /// 16-bit checksum.
    Bits16,
    /// 32-bit checksum.
    Bits32,
}

impl ChecksumBitSize {
    /// Number of bytes for this bit size.
    pub fn num_bytes(&self) -> usize {
        match self {
            Self::Bits8 => 1,
            Self::Bits16 => 2,
            Self::Bits32 => 4,
        }
    }

    /// Bit width (8, 16, or 32).
    pub fn bits(&self) -> usize {
        self.num_bytes() * 8
    }
}

/// Basic byte-level checksum algorithm.
///
/// Supports 8-bit, 16-bit, and 32-bit checksums with configurable
/// accumulation mode (addition vs XOR) and complement options.
///
/// Ported from `ghidra.app.plugin.core.checksums.BasicChecksumAlgorithm`.
pub struct BasicChecksum {
    size: ChecksumBitSize,
}

impl BasicChecksum {
    /// Create a new basic checksum with the given bit size.
    pub fn new(size: ChecksumBitSize) -> Self {
        Self { size }
    }
}

impl ChecksumAlgorithm for BasicChecksum {
    fn name(&self) -> &str {
        match self.size {
            ChecksumBitSize::Bits8 => "Checksum-8",
            ChecksumBitSize::Bits16 => "Checksum-16",
            ChecksumBitSize::Bits32 => "Checksum-32",
        }
    }

    fn compute(&self, data: &[u8], options: &ChecksumOptions) -> Vec<u8> {
        let num_bytes = self.size.num_bytes();
        let mut sum: u64 = 0;
        let max = 1u64 << (num_bytes * 8);

        for (i, &b) in data.iter().enumerate() {
            let next = if num_bytes == 1 {
                b as u64
            } else {
                (b as u64) << ((num_bytes - 1 - i % num_bytes) * 8)
            };

            if options.xor {
                sum ^= next;
            } else {
                sum += next;
            }
        }

        // Handle carry (fold upper bits back in).
        if options.carry {
            while sum >= max {
                sum = (sum & (max - 1)) + (sum >> (num_bytes * 8));
            }
        }

        // Handle complement.
        if options.ones_complement {
            sum = !sum;
        } else if options.twos_complement {
            sum = (-(sum as i64)) as u64;
        }

        to_le_bytes(sum, num_bytes)
    }

    fn supports_decimal(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Checksum-8 / Checksum-16 / Checksum-32
// ---------------------------------------------------------------------------

/// 8-bit basic checksum.
pub struct Checksum8Algorithm;

impl Checksum8Algorithm {
    pub fn new() -> BasicChecksum {
        BasicChecksum::new(ChecksumBitSize::Bits8)
    }
}

/// 16-bit basic checksum.
pub struct Checksum16Algorithm;

impl Checksum16Algorithm {
    pub fn new() -> BasicChecksum {
        BasicChecksum::new(ChecksumBitSize::Bits16)
    }
}

/// 32-bit basic checksum.
pub struct Checksum32Algorithm;

impl Checksum32Algorithm {
    pub fn new() -> BasicChecksum {
        BasicChecksum::new(ChecksumBitSize::Bits32)
    }
}

// ---------------------------------------------------------------------------
// CRC-16
// ---------------------------------------------------------------------------

/// CRC-16 (polynomial 0x8005, no bit reversal).
///
/// Ported from `CRC16ChecksumAlgorithm`.
pub struct Crc16Algorithm;

impl Crc16Algorithm {
    pub fn new() -> Self {
        Self
    }
}

impl ChecksumAlgorithm for Crc16Algorithm {
    fn name(&self) -> &str {
        "CRC-16"
    }

    fn compute(&self, data: &[u8], options: &ChecksumOptions) -> Vec<u8> {
        let mut crc: u16 = 0;
        for &b in data {
            crc ^= (b as u16) << 8;
            for _ in 0..8 {
                if crc & 0x8000 != 0 {
                    crc = (crc << 1) ^ 0x8005;
                } else {
                    crc <<= 1;
                }
            }
        }
        let mut val = crc as u64;
        if options.ones_complement {
            val = !val & 0xFFFF;
        } else if options.twos_complement {
            val = (-(val as i64)) as u64 & 0xFFFF;
        }
        to_le_bytes(val, 2)
    }

    fn supports_decimal(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// CRC-16/CCITT
// ---------------------------------------------------------------------------

/// CRC-16/CCITT (polynomial 0x1021, initial value 0xFFFF).
///
/// Ported from `CRC16CCITTChecksumAlgorithm`.
pub struct Crc16CcittAlgorithm;

impl Crc16CcittAlgorithm {
    pub fn new() -> Self {
        Self
    }
}

impl ChecksumAlgorithm for Crc16CcittAlgorithm {
    fn name(&self) -> &str {
        "CRC-16/CCITT"
    }

    fn compute(&self, data: &[u8], options: &ChecksumOptions) -> Vec<u8> {
        let mut crc: u16 = 0xFFFF;
        for &b in data {
            crc ^= (b as u16) << 8;
            for _ in 0..8 {
                if crc & 0x8000 != 0 {
                    crc = (crc << 1) ^ 0x1021;
                } else {
                    crc <<= 1;
                }
            }
        }
        let mut val = crc as u64;
        if options.ones_complement {
            val = !val & 0xFFFF;
        } else if options.twos_complement {
            val = (-(val as i64)) as u64 & 0xFFFF;
        }
        to_le_bytes(val, 2)
    }

    fn supports_decimal(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// CRC-32
// ---------------------------------------------------------------------------

/// CRC-32 using the standard polynomial (0xEDB88320, reflected).
///
/// Ported from `CRC32ChecksumAlgorithm`.
pub struct Crc32Algorithm;

impl Crc32Algorithm {
    pub fn new() -> Self {
        Self
    }
}

/// Build the CRC-32 lookup table (reflected polynomial 0xEDB88320).
fn build_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    for i in 0..256 {
        let mut crc = i as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        table[i] = crc;
    }
    table
}

/// Compute CRC-32 over data using the standard reflected algorithm.
pub fn crc32(data: &[u8]) -> u32 {
    let table = build_crc32_table();
    let mut crc = 0xFFFFFFFF_u32;
    for &b in data {
        let idx = ((crc ^ b as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[idx];
    }
    !crc
}

impl ChecksumAlgorithm for Crc32Algorithm {
    fn name(&self) -> &str {
        "CRC-32"
    }

    fn compute(&self, data: &[u8], options: &ChecksumOptions) -> Vec<u8> {
        let mut val = crc32(data) as u64;

        if options.ones_complement {
            val = !val & 0xFFFF_FFFF;
        } else if options.twos_complement {
            val = (-(val as i64)) as u64 & 0xFFFF_FFFF;
        }
        to_le_bytes(val, 4)
    }

    fn supports_decimal(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Adler-32
// ---------------------------------------------------------------------------

/// Adler-32 checksum algorithm.
///
/// Ported from `Adler32ChecksumAlgorithm`.
pub struct Adler32Algorithm;

impl Adler32Algorithm {
    pub fn new() -> Self {
        Self
    }
}

/// Compute the Adler-32 checksum over data.
pub fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

impl ChecksumAlgorithm for Adler32Algorithm {
    fn name(&self) -> &str {
        "Adler-32"
    }

    fn compute(&self, data: &[u8], options: &ChecksumOptions) -> Vec<u8> {
        let mut val = adler32(data) as u64;

        if options.ones_complement {
            val = !val & 0xFFFF_FFFF;
        } else if options.twos_complement {
            val = (-(val as i64)) as u64 & 0xFFFF_FFFF;
        }
        to_le_bytes(val, 4)
    }

    fn supports_decimal(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Digest algorithms (MD5, SHA-1, SHA-256, SHA-384, SHA-512)
// ---------------------------------------------------------------------------

/// Supported message digest types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestType {
    /// MD5 (128-bit / 16 bytes).
    Md5,
    /// SHA-1 (160-bit / 20 bytes).
    Sha1,
    /// SHA-256 (256-bit / 32 bytes).
    Sha256,
    /// SHA-384 (384-bit / 48 bytes).
    Sha384,
    /// SHA-512 (512-bit / 64 bytes).
    Sha512,
}

/// Generic message digest checksum algorithm.
///
/// Uses the `md-5` and `sha2` crates for digest computation.
/// Ported from `DigestChecksumAlgorithm` and its subclasses.
pub struct DigestChecksum {
    digest_type: DigestType,
}

impl DigestChecksum {
    /// Create a new digest checksum of the given type.
    pub fn new(digest_type: DigestType) -> Self {
        Self { digest_type }
    }

    /// Create an MD5 checksum.
    pub fn md5() -> Self {
        Self::new(DigestType::Md5)
    }

    /// Create a SHA-1 checksum.
    pub fn sha1() -> Self {
        Self::new(DigestType::Sha1)
    }

    /// Create a SHA-256 checksum.
    pub fn sha256() -> Self {
        Self::new(DigestType::Sha256)
    }

    /// Create a SHA-384 checksum.
    pub fn sha384() -> Self {
        Self::new(DigestType::Sha384)
    }

    /// Create a SHA-512 checksum.
    pub fn sha512() -> Self {
        Self::new(DigestType::Sha512)
    }
}

impl ChecksumAlgorithm for DigestChecksum {
    fn name(&self) -> &str {
        match self.digest_type {
            DigestType::Md5 => "MD5",
            DigestType::Sha1 => "SHA-1",
            DigestType::Sha256 => "SHA-256",
            DigestType::Sha384 => "SHA-384",
            DigestType::Sha512 => "SHA-512",
        }
    }

    fn compute(&self, data: &[u8], _options: &ChecksumOptions) -> Vec<u8> {
        use md5::Digest;
        match self.digest_type {
            DigestType::Md5 => {
                let mut hasher = md5::Md5::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            DigestType::Sha1 => {
                use sha1::Digest as _;
                let mut hasher = sha1::Sha1::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            DigestType::Sha256 => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            DigestType::Sha384 => {
                let mut hasher = sha2::Sha384::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            DigestType::Sha512 => {
                let mut hasher = sha2::Sha512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
        }
    }
}

/// Convenience type alias for MD5.
pub type Md5Algorithm = DigestChecksum;

/// Convenience type alias for SHA-1.
pub type Sha1Algorithm = DigestChecksum;

/// Convenience type alias for SHA-256.
pub type Sha256Algorithm = DigestChecksum;

/// Convenience type alias for SHA-384.
pub type Sha384Algorithm = DigestChecksum;

/// Convenience type alias for SHA-512.
pub type Sha512Algorithm = DigestChecksum;

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Return a vector of all built-in checksum algorithms.
///
/// This corresponds to the set of algorithms discovered by Ghidra's
/// `ExtensionPoint` mechanism for `ChecksumAlgorithm`.
pub fn all_algorithms() -> Vec<Box<dyn ChecksumAlgorithm>> {
    vec![
        Box::new(BasicChecksum::new(ChecksumBitSize::Bits8)),
        Box::new(BasicChecksum::new(ChecksumBitSize::Bits16)),
        Box::new(BasicChecksum::new(ChecksumBitSize::Bits32)),
        Box::new(Crc16Algorithm::new()),
        Box::new(Crc16CcittAlgorithm::new()),
        Box::new(Crc32Algorithm::new()),
        Box::new(Adler32Algorithm::new()),
        Box::new(DigestChecksum::md5()),
        Box::new(DigestChecksum::sha1()),
        Box::new(DigestChecksum::sha256()),
        Box::new(DigestChecksum::sha384()),
        Box::new(DigestChecksum::sha512()),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_checksum_8() {
        let algo = BasicChecksum::new(ChecksumBitSize::Bits8);
        let data = b"ABC"; // 0x41 + 0x42 + 0x43 = 0xC6
        let result = algo.compute(data, &ChecksumOptions::default());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], 0xC6);
    }

    #[test]
    fn test_basic_checksum_8_xor() {
        let algo = BasicChecksum::new(ChecksumBitSize::Bits8);
        let data = b"ABC"; // 0x41 ^ 0x42 ^ 0x43 = 0x40
        let opts = ChecksumOptions {
            xor: true,
            ..Default::default()
        };
        let result = algo.compute(data, &opts);
        assert_eq!(result[0], 0x40);
    }

    #[test]
    fn test_basic_checksum_16() {
        let algo = BasicChecksum::new(ChecksumBitSize::Bits16);
        let result = algo.compute(b"AB", &ChecksumOptions::default());
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_basic_checksum_32() {
        let algo = BasicChecksum::new(ChecksumBitSize::Bits32);
        let result = algo.compute(b"Hello", &ChecksumOptions::default());
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn test_crc32_known_value() {
        // CRC-32 of "123456789" should be 0xCBF43926.
        let crc = crc32(b"123456789");
        assert_eq!(crc, 0xCBF43926);
    }

    #[test]
    fn test_crc32_algorithm() {
        let algo = Crc32Algorithm::new();
        assert_eq!(algo.name(), "CRC-32");
        let result = algo.compute(b"123456789", &ChecksumOptions::default());
        assert_eq!(result.len(), 4);
        // Check it matches known value (little-endian).
        let val = u32::from_le_bytes([result[0], result[1], result[2], result[3]]);
        assert_eq!(val, 0xCBF43926);
    }

    #[test]
    fn test_crc16() {
        let algo = Crc16Algorithm::new();
        assert_eq!(algo.name(), "CRC-16");
        let result = algo.compute(b"123456789", &ChecksumOptions::default());
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_crc16_ccitt() {
        let algo = Crc16CcittAlgorithm::new();
        assert_eq!(algo.name(), "CRC-16/CCITT");
        let result = algo.compute(b"123456789", &ChecksumOptions::default());
        assert_eq!(result.len(), 2);
        // Known CRC-16/CCITT of "123456789" is 0x29B1.
        let val = u16::from_le_bytes([result[0], result[1]]);
        assert_eq!(val, 0x29B1);
    }

    #[test]
    fn test_adler32_known() {
        // Adler-32 of "Wikipedia" should be 0x11E60398.
        let val = adler32(b"Wikipedia");
        assert_eq!(val, 0x11E60398);
    }

    #[test]
    fn test_adler32_algorithm() {
        let algo = Adler32Algorithm::new();
        assert_eq!(algo.name(), "Adler-32");
        assert!(algo.supports_decimal());
        let result = algo.compute(b"Wikipedia", &ChecksumOptions::default());
        assert_eq!(result.len(), 4);
        let val = u32::from_le_bytes([result[0], result[1], result[2], result[3]]);
        assert_eq!(val, 0x11E60398);
    }

    #[test]
    fn test_md5_known() {
        let algo = DigestChecksum::md5();
        assert_eq!(algo.name(), "MD5");
        let result = algo.compute(b"hello", &ChecksumOptions::default());
        assert_eq!(result.len(), 16);
        // MD5 of "hello" = 5d41402abc4b2a76b9719d911017c592
        assert_eq!(format_hex(&result), "5D41402ABC4B2A76B9719D911017C592");
    }

    #[test]
    fn test_sha1() {
        let algo = DigestChecksum::sha1();
        assert_eq!(algo.name(), "SHA-1");
        let result = algo.compute(b"hello", &ChecksumOptions::default());
        assert_eq!(result.len(), 20);
    }

    #[test]
    fn test_sha256() {
        let algo = DigestChecksum::sha256();
        assert_eq!(algo.name(), "SHA-256");
        let result = algo.compute(b"hello", &ChecksumOptions::default());
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_sha384() {
        let algo = DigestChecksum::sha384();
        let result = algo.compute(b"hello", &ChecksumOptions::default());
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn test_sha512() {
        let algo = DigestChecksum::sha512();
        let result = algo.compute(b"hello", &ChecksumOptions::default());
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_format_hex() {
        assert_eq!(format_hex(&[0xAB, 0xCD, 0xEF]), "ABCDEF");
        assert_eq!(format_hex(&[]), "");
    }

    #[test]
    fn test_format_decimal() {
        assert_eq!(format_decimal(&[0x39, 0x30, 0x00, 0x00]), "12345");
        assert_eq!(format_decimal(&[]), "");
    }

    #[test]
    fn test_to_le_bytes() {
        assert_eq!(to_le_bytes(0x1234, 2), vec![0x34, 0x12]);
        assert_eq!(to_le_bytes(0xFF, 1), vec![0xFF]);
        assert_eq!(to_le_bytes(0, 4), vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_ones_complement() {
        let algo = Crc32Algorithm::new();
        let opts_normal = ChecksumOptions::default();
        let opts_ones = ChecksumOptions {
            ones_complement: true,
            ..Default::default()
        };
        let r1 = algo.compute(b"test", &opts_normal);
        let r2 = algo.compute(b"test", &opts_ones);
        // They should be different when complement is applied.
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_all_algorithms() {
        let algos = all_algorithms();
        assert_eq!(algos.len(), 12);
        for algo in &algos {
            let result = algo.compute(b"test data", &ChecksumOptions::default());
            assert!(!result.is_empty(), "Algorithm {} returned empty result", algo.name());
        }
    }

    #[test]
    fn test_empty_data() {
        let algo = Crc32Algorithm::new();
        let result = algo.compute(&[], &ChecksumOptions::default());
        assert_eq!(result.len(), 4);
        // CRC-32 of empty data.
        let val = u32::from_le_bytes([result[0], result[1], result[2], result[3]]);
        assert_eq!(val, 0x00000000); // CRC-32 of empty is 0.
    }

    #[test]
    fn test_twos_complement_basic() {
        let algo = BasicChecksum::new(ChecksumBitSize::Bits8);
        let opts = ChecksumOptions::with_twos_complement();
        let result = algo.compute(&[1, 2, 3], &opts);
        // 1+2+3 = 6, two's complement = 250
        assert_eq!(result[0], 250);
    }
}
