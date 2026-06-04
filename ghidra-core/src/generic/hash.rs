//! Hash utilities for Ghidra Rust.
//!
//! Ports Ghidra's `generic.hash` package: `MessageDigest` trait, CRC32,
//! FNV-1a 32/64-bit digests, and `HashUtilities`.

use std::io::Read;

// ============================================================================
// MessageDigest trait
// ============================================================================

/// Trait for message digest algorithms (Ghidra `MessageDigest` interface).
pub trait MessageDigest: Send {
    /// Returns the algorithm name.
    fn algorithm(&self) -> &str;

    /// Returns the digest length in bytes.
    fn digest_length(&self) -> usize;

    /// Update digest with a single byte.
    fn update_byte(&mut self, input: u8);

    /// Update digest with a big-endian short.
    fn update_short(&mut self, input: u16) {
        self.update_bytes(&input.to_be_bytes());
    }

    /// Update digest with a big-endian int.
    fn update_int(&mut self, input: u32) {
        self.update_bytes(&input.to_be_bytes());
    }

    /// Update digest with a big-endian long.
    fn update_long(&mut self, input: u64) {
        self.update_bytes(&input.to_be_bytes());
    }

    /// Update digest with byte array.
    fn update_bytes(&mut self, input: &[u8]);

    /// Update digest with a sub-range of a byte array.
    fn update_range(&mut self, input: &[u8], offset: usize, len: usize) {
        self.update_bytes(&input[offset..offset + len]);
    }

    /// Complete the computation and return the digest bytes.
    /// The digest is reset after this call.
    fn digest(&mut self) -> Vec<u8>;

    /// Complete the computation and return (up to) the first 8 bytes as a
    /// big-endian `u64`. The digest is reset after this call.
    fn digest_long(&mut self) -> u64 {
        let d = self.digest();
        let mut result = 0u64;
        for (i, &b) in d.iter().take(8).enumerate() {
            result |= (b as u64) << (56 - i * 8);
        }
        result
    }

    /// Reset the digest for further use.
    fn reset(&mut self);
}

// ============================================================================
// SimpleCRC32
// ============================================================================

/// CRC32 lookup table and single-byte hash function.
///
/// Corresponds to Ghidra's `generic.hash.SimpleCRC32`.
pub struct SimpleCrc32;

impl SimpleCrc32 {
    /// Standard CRC32 polynomial table.
    pub fn hash_one_byte(hashcode: i32, val: i32) -> i32 {
        let idx = ((hashcode ^ val) & 0xFF) as usize;
        CRC32_TABLE[idx] ^ ((hashcode as u32) >> 8) as i32
    }
}

/// Compute CRC32 over a byte slice.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        let idx = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = CRC32_TABLE_U32[idx] ^ (crc >> 8);
    }
    !crc
}

/// CRC32 table as `u32` for the `crc32()` function.
static CRC32_TABLE_U32: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

// The Java-style CRC32 table (for `hash_one_byte` compatibility)
static CRC32_TABLE: [i32; 256] = {
    let mut table = [0i32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as i32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ -306674912; // 0xEDB88320 as signed i32
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

// ============================================================================
// FNV-1a 32-bit digest
// ============================================================================

/// FNV-1a 32-bit message digest.
///
/// Corresponds to Ghidra's `generic.hash.FNV1a32MessageDigest`.
pub struct Fnv1a32Digest {
    hash: u32,
}

impl Fnv1a32Digest {
    pub const FNV_32_OFFSET_BASIS: u32 = 0x811c9dc5;
    pub const FNV_32_PRIME: u32 = 16777619;

    pub fn new() -> Self {
        Self {
            hash: Self::FNV_32_OFFSET_BASIS,
        }
    }

    pub fn with_initial_vector(iv: u32) -> Self {
        Self { hash: iv }
    }
}

impl Default for Fnv1a32Digest {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageDigest for Fnv1a32Digest {
    fn algorithm(&self) -> &str {
        "FNV-1a"
    }

    fn digest_length(&self) -> usize {
        4
    }

    fn update_byte(&mut self, input: u8) {
        self.hash ^= input as u32;
        self.hash = self.hash.wrapping_mul(Self::FNV_32_PRIME);
    }

    fn update_bytes(&mut self, input: &[u8]) {
        for &b in input {
            self.hash ^= b as u32;
            self.hash = self.hash.wrapping_mul(Self::FNV_32_PRIME);
        }
    }

    fn digest(&mut self) -> Vec<u8> {
        let result = self.hash.to_le_bytes().to_vec();
        self.reset();
        result
    }

    fn digest_long(&mut self) -> u64 {
        let result = self.hash as u64;
        self.reset();
        result
    }

    fn reset(&mut self) {
        self.hash = Self::FNV_32_OFFSET_BASIS;
    }
}

// ============================================================================
// FNV-1a 64-bit digest
// ============================================================================

/// FNV-1a 64-bit message digest.
///
/// Corresponds to Ghidra's `generic.hash.FNV1a64MessageDigest`.
pub struct Fnv1a64Digest {
    hash: u64,
}

impl Fnv1a64Digest {
    pub const FNV_64_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    pub const FNV_64_PRIME: u64 = 0x00000100000001B3;

    pub fn new() -> Self {
        Self {
            hash: Self::FNV_64_OFFSET_BASIS,
        }
    }

    pub fn with_initial_vector(iv: u64) -> Self {
        Self { hash: iv }
    }
}

impl Default for Fnv1a64Digest {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageDigest for Fnv1a64Digest {
    fn algorithm(&self) -> &str {
        "FNV-1a-64"
    }

    fn digest_length(&self) -> usize {
        8
    }

    fn update_byte(&mut self, input: u8) {
        self.hash ^= input as u64;
        self.hash = self.hash.wrapping_mul(Self::FNV_64_PRIME);
    }

    fn update_bytes(&mut self, input: &[u8]) {
        for &b in input {
            self.hash ^= b as u64;
            self.hash = self.hash.wrapping_mul(Self::FNV_64_PRIME);
        }
    }

    fn digest(&mut self) -> Vec<u8> {
        let result = self.hash.to_le_bytes().to_vec();
        self.reset();
        result
    }

    fn digest_long(&mut self) -> u64 {
        let result = self.hash;
        self.reset();
        result
    }

    fn reset(&mut self) {
        self.hash = Self::FNV_64_OFFSET_BASIS;
    }
}

// ============================================================================
// HashUtilities
// ============================================================================

/// Utility methods for hashing files, strings, and byte arrays.
///
/// Corresponds to Ghidra's `generic.hash.HashUtilities`.
pub mod hash_utilities {
    use super::*;

    pub const MD5_ALGORITHM: &str = "MD5";
    pub const SHA256_ALGORITHM: &str = "SHA-256";

    pub const SALT_LENGTH: usize = 4;
    pub const MD5_UNSALTED_HASH_LENGTH: usize = 32;
    pub const MD5_SALTED_HASH_LENGTH: usize = MD5_UNSALTED_HASH_LENGTH + SALT_LENGTH;
    pub const SHA256_UNSALTED_HASH_LENGTH: usize = 64;
    pub const SHA256_SALTED_HASH_LENGTH: usize = SHA256_UNSALTED_HASH_LENGTH + SALT_LENGTH;

    /// Compute the SHA-256 hash of a byte slice and return as a hex string.
    pub fn get_sha256_hash(data: &[u8]) -> String {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    /// Compute the MD5 hash of a byte slice and return as a hex string.
    pub fn get_md5_hash(data: &[u8]) -> String {
        use md5::Digest;
        let mut hasher = md5::Md5::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    /// Compute the hash of a file at the given path using SHA-256.
    pub fn get_file_hash(path: &std::path::Path) -> std::io::Result<String> {
        let data = std::fs::read(path)?;
        Ok(get_sha256_hash(&data))
    }

    /// Compute a hash using a streaming reader (SHA-256).
    pub fn get_hash_from_reader(reader: &mut impl Read) -> std::io::Result<String> {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Convert binary data to hex string.
    pub fn hex_dump(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32() {
        let hash = crc32(b"hello");
        assert_ne!(hash, 0);
        // Deterministic
        assert_eq!(hash, crc32(b"hello"));
        // Different data => different hash
        assert_ne!(hash, crc32(b"world"));
    }

    #[test]
    fn test_fnv1a32_basic() {
        let mut digest = Fnv1a32Digest::new();
        digest.update_bytes(b"hello");
        let result = digest.digest_long();
        assert_ne!(result, 0);
    }

    #[test]
    fn test_fnv1a32_reset() {
        let mut digest = Fnv1a32Digest::new();
        digest.update_bytes(b"hello");
        let h1 = digest.digest_long();
        // After digest(), it should reset
        digest.update_bytes(b"hello");
        let h2 = digest.digest_long();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_fnv1a32_range() {
        let mut digest = Fnv1a32Digest::new();
        let data = b"xxHELLOxx";
        digest.update_range(data, 2, 5);
        let h1 = digest.digest_long();

        let mut digest2 = Fnv1a32Digest::new();
        digest2.update_bytes(b"HELLO");
        let h2 = digest2.digest_long();

        assert_eq!(h1, h2);
    }

    #[test]
    fn test_fnv1a64_basic() {
        let mut digest = Fnv1a64Digest::new();
        digest.update_bytes(b"hello");
        let result = digest.digest_long();
        assert_ne!(result, 0);
    }

    #[test]
    fn test_fnv1a64_deterministic() {
        let mut d1 = Fnv1a64Digest::new();
        d1.update_bytes(b"test data");
        let h1 = d1.digest_long();

        let mut d2 = Fnv1a64Digest::new();
        d2.update_bytes(b"test data");
        let h2 = d2.digest_long();

        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_utilities_hex_dump() {
        assert_eq!(hash_utilities::hex_dump(&[0xAB, 0xCD, 0xEF]), "abcdef");
        assert_eq!(hash_utilities::hex_dump(&[0x00, 0xFF]), "00ff");
    }

    #[test]
    fn test_hash_utilities_sha256() {
        let hash = hash_utilities::get_sha256_hash(b"hello");
        assert_eq!(hash.len(), 64);
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_hash_utilities_md5() {
        let hash = hash_utilities::get_md5_hash(b"hello");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_fnv1a32_digest_bytes() {
        let mut digest = Fnv1a32Digest::new();
        digest.update_bytes(b"test");
        let bytes = digest.digest();
        assert_eq!(bytes.len(), 4);
    }

    #[test]
    fn test_fnv1a64_digest_bytes() {
        let mut digest = Fnv1a64Digest::new();
        digest.update_bytes(b"test");
        let bytes = digest.digest();
        assert_eq!(bytes.len(), 8);
    }

    #[test]
    fn test_message_digest_int_long() {
        let mut digest = Fnv1a64Digest::new();
        digest.update_int(42);
        let h1 = digest.digest_long();

        let mut digest2 = Fnv1a64Digest::new();
        digest2.update_bytes(&42u32.to_be_bytes());
        let h2 = digest2.digest_long();

        assert_eq!(h1, h2);
    }
}
