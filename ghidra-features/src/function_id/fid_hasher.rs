//! Function hashing for FID.
//!
//! Ported from Ghidra's `HashFamily`, `HashMatch`, and `FidHasherFactory`.
//!
//! Provides multiple hash strategies for computing function signatures:
//!
//! - **FullBody**: Hash of the entire function body.
//! - **TrimmedBody**: Hash after removing prologue/epilogue and relocations.
//! - **InstructionOnly**: Hash of only the instruction bytes (no immediates
//!   or displacement fields).
//! - **MnemonicSequence**: Hash of the instruction mnemonic sequence.
//!
//! Using multiple hash families increases the chance of matching a function
//! even when minor changes occur between library versions.

use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// ---------------------------------------------------------------------------
// HashFamily
// ---------------------------------------------------------------------------

/// A family of hash functions used for function identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashFamily {
    /// Hash of the full function body bytes.
    FullBody,
    /// Hash after stripping prologue and epilogue bytes.
    TrimmedBody,
    /// Hash of instruction opcodes only (immediate values masked out).
    InstructionOnly,
    /// Hash of the mnemonic sequence (instruction names only).
    MnemonicSequence,
    /// CRC32-based hash.
    Crc32,
    /// A custom hash family.
    Custom(u32),
}

impl HashFamily {
    /// All standard hash families.
    pub fn all_standard() -> Vec<Self> {
        vec![
            Self::FullBody,
            Self::TrimmedBody,
            Self::InstructionOnly,
            Self::MnemonicSequence,
            Self::Crc32,
        ]
    }

    /// Human-readable name for the hash family.
    pub fn name(&self) -> &str {
        match self {
            Self::FullBody => "FullBody",
            Self::TrimmedBody => "TrimmedBody",
            Self::InstructionOnly => "InstructionOnly",
            Self::MnemonicSequence => "MnemonicSequence",
            Self::Crc32 => "Crc32",
            Self::Custom(_) => "Custom",
        }
    }
}

// ---------------------------------------------------------------------------
// FidHasher -- computes function hashes
// ---------------------------------------------------------------------------

/// Computes function hashes using multiple hash families.
#[derive(Debug)]
pub struct FidHasher {
    /// The hash families to use.
    pub families: Vec<HashFamily>,
}

impl FidHasher {
    /// Create a hasher with all standard hash families.
    pub fn new() -> Self {
        Self {
            families: HashFamily::all_standard(),
        }
    }

    /// Create a hasher with specific hash families.
    pub fn with_families(families: Vec<HashFamily>) -> Self {
        Self { families }
    }

    /// Compute all configured hashes for a function body.
    pub fn compute_hashes(&self, body: &[u8]) -> Vec<(HashFamily, u64)> {
        self.families
            .iter()
            .map(|&family| {
                let hash = match family {
                    HashFamily::FullBody => self.hash_full_body(body),
                    HashFamily::TrimmedBody => self.hash_trimmed_body(body),
                    HashFamily::InstructionOnly => self.hash_instruction_only(body),
                    HashFamily::MnemonicSequence => self.hash_mnemonic_sequence(body),
                    HashFamily::Crc32 => self.hash_crc32(body),
                    HashFamily::Custom(id) => self.hash_custom(body, id),
                };
                (family, hash)
            })
            .collect()
    }

    /// Hash the full function body.
    fn hash_full_body(&self, body: &[u8]) -> u64 {
        let mut hasher = DefaultHasher::new();
        body.hash(&mut hasher);
        hasher.finish()
    }

    /// Hash a trimmed body (remove first and last N bytes to skip
    /// prologue/epilogue).
    fn hash_trimmed_body(&self, body: &[u8]) -> u64 {
        let trim = body.len().min(8);
        if body.len() <= trim * 2 {
            return self.hash_full_body(body);
        }
        let trimmed = &body[trim..body.len() - trim];
        let mut hasher = DefaultHasher::new();
        trimmed.hash(&mut hasher);
        hasher.finish()
    }

    /// Hash instruction-only bytes (mask out bytes that are likely
    /// immediate/displacement values).
    ///
    /// Simple heuristic: mask out every 4th byte group (common for x86
    /// immediates).
    fn hash_instruction_only(&self, body: &[u8]) -> u64 {
        let mut masked = body.to_vec();
        // Simple mask: zero out bytes at positions where immediates typically live
        // In practice, this would be architecture-specific.
        for chunk in masked.chunks_exact_mut(4) {
            chunk[3] = 0; // mask last byte of each 4-byte group
        }
        let mut hasher = DefaultHasher::new();
        masked.hash(&mut hasher);
        hasher.finish()
    }

    /// Hash the mnemonic sequence (placeholder: in a real implementation,
    /// this would decode instructions and hash only mnemonics).
    fn hash_mnemonic_sequence(&self, body: &[u8]) -> u64 {
        // Placeholder: use the instruction-only hash as a proxy
        self.hash_instruction_only(body)
    }

    /// CRC32-based hash.
    fn hash_crc32(&self, body: &[u8]) -> u64 {
        // Use a simple CRC32-like computation
        let mut crc: u32 = 0xFFFFFFFF;
        for &byte in body {
            crc ^= byte as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc >>= 1;
                }
            }
        }
        (!crc) as u64
    }

    /// Custom hash (uses the id as a seed).
    fn hash_custom(&self, body: &[u8], id: u32) -> u64 {
        let mut hasher = DefaultHasher::new();
        id.hash(&mut hasher);
        body.hash(&mut hasher);
        hasher.finish()
    }
}

impl Default for FidHasher {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// HashMatch
// ---------------------------------------------------------------------------

/// The result of matching a function hash against the FID database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashMatch {
    /// The hash family that matched.
    pub family: HashFamily,
    /// The computed hash value.
    pub hash: u64,
    /// The matched function record ID.
    pub function_id: i64,
    /// The matched function name.
    pub function_name: String,
    /// The library the match came from.
    pub library_name: String,
    /// Confidence (1.0 for exact hash match, lower for weaker families).
    pub confidence: f64,
}

impl HashMatch {
    /// Create a new hash match.
    pub fn new(
        family: HashFamily,
        hash: u64,
        function_id: i64,
        function_name: impl Into<String>,
        library_name: impl Into<String>,
    ) -> Self {
        let confidence = match family {
            HashFamily::FullBody => 1.0,
            HashFamily::TrimmedBody => 0.9,
            HashFamily::InstructionOnly => 0.85,
            HashFamily::MnemonicSequence => 0.8,
            HashFamily::Crc32 => 0.95,
            HashFamily::Custom(_) => 0.5,
        };
        Self {
            family,
            hash,
            function_id,
            function_name: function_name.into(),
            library_name: library_name.into(),
            confidence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fid_hasher_full_body() {
        let hasher = FidHasher::with_families(vec![HashFamily::FullBody]);
        let hashes = hasher.compute_hashes(b"hello world");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].0, HashFamily::FullBody);
        assert_ne!(hashes[0].1, 0);
    }

    #[test]
    fn test_fid_hasher_consistency() {
        let hasher = FidHasher::new();
        let h1 = hasher.compute_hashes(&[0x55, 0x89, 0xE5, 0x83, 0xEC, 0x10]);
        let h2 = hasher.compute_hashes(&[0x55, 0x89, 0xE5, 0x83, 0xEC, 0x10]);
        for ((f1, v1), (f2, v2)) in h1.iter().zip(h2.iter()) {
            assert_eq!(f1, f2);
            assert_eq!(v1, v2);
        }
    }

    #[test]
    fn test_fid_hasher_different_inputs() {
        let hasher = FidHasher::with_families(vec![HashFamily::FullBody]);
        let h1 = hasher.compute_hashes(b"aaaa");
        let h2 = hasher.compute_hashes(b"bbbb");
        assert_ne!(h1[0].1, h2[0].1);
    }

    #[test]
    fn test_trimmed_body_hash() {
        let hasher = FidHasher::with_families(vec![HashFamily::TrimmedBody]);
        let body = [0u8; 32];
        let hashes = hasher.compute_hashes(&body);
        assert_eq!(hashes.len(), 1);
        assert_ne!(hashes[0].1, 0);
    }

    #[test]
    fn test_trimmed_body_short() {
        let hasher = FidHasher::with_families(vec![HashFamily::TrimmedBody]);
        let body = [0u8; 4]; // too short to trim, should fall back to full body
        let hashes = hasher.compute_hashes(&body);
        assert_eq!(hashes.len(), 1);
    }

    #[test]
    fn test_crc32_hash() {
        let hasher = FidHasher::with_families(vec![HashFamily::Crc32]);
        let hashes = hasher.compute_hashes(b"test data");
        assert_eq!(hashes[0].0, HashFamily::Crc32);
        assert_ne!(hashes[0].1, 0);
    }

    #[test]
    fn test_all_standard_families() {
        let hasher = FidHasher::new();
        let hashes = hasher.compute_hashes(&[0x55, 0x89, 0xE5]);
        assert_eq!(hashes.len(), 5); // all 5 standard families
    }

    #[test]
    fn test_hash_match_confidence() {
        let m = HashMatch::new(HashFamily::FullBody, 0x1234, 1, "memcpy", "libc.so");
        assert_eq!(m.confidence, 1.0);

        let m2 = HashMatch::new(HashFamily::TrimmedBody, 0x5678, 2, "strlen", "libc.so");
        assert_eq!(m2.confidence, 0.9);
    }

    #[test]
    fn test_hash_family_name() {
        assert_eq!(HashFamily::FullBody.name(), "FullBody");
        assert_eq!(HashFamily::Crc32.name(), "Crc32");
        assert_eq!(HashFamily::Custom(1).name(), "Custom");
    }

    #[test]
    fn test_hash_family_all_standard() {
        let families = HashFamily::all_standard();
        assert_eq!(families.len(), 5);
    }
}
