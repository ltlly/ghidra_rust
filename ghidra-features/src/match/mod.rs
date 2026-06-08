//! Function Matching for Version Tracking
//!
//! Ported from `ghidra.app.plugin.match`.
//!
//! Provides function hashing and matching utilities for comparing programs
//! across versions. Supports exact bytes, exact instructions, and exact
//! mnemonics matching strategies.

use std::collections::HashMap;

/// Trait for computing a hash of a function's content.
///
/// Different implementations can hash bytes, instructions, or mnemonics.
pub trait FunctionHasher: Send + Sync + std::fmt::Debug {
    /// Hash a function's body, returning a 64-bit hash value.
    fn hash(&self, function_bytes: &[u8]) -> u64;

    /// Count the common bits between two functions.
    ///
    /// Returns the number of bits that are the same between the two
    /// functions' representations.
    fn common_bit_count(&self, func_a: &[u8], func_b: &[u8]) -> usize;
}

/// Hasher that computes an FNV-1a 64-bit hash over the raw bytes of a function.
#[derive(Debug, Clone)]
pub struct ExactBytesFunctionHasher;

impl ExactBytesFunctionHasher {
    /// Singleton instance.
    pub const INSTANCE: ExactBytesFunctionHasher = ExactBytesFunctionHasher;
}

impl FunctionHasher for ExactBytesFunctionHasher {
    fn hash(&self, function_bytes: &[u8]) -> u64 {
        fnv1a64(function_bytes)
    }

    fn common_bit_count(&self, func_a: &[u8], _func_b: &[u8]) -> usize {
        func_a.len() * 8
    }
}

/// Hasher that computes an FNV-1a 64-bit hash over the instruction bytes
/// of a function, masking out operand-specific bits.
///
/// This produces hashes that match when two functions have the same
/// instruction sequence, even if operand values differ slightly.
#[derive(Debug, Clone)]
pub struct ExactInstructionsFunctionHasher;

impl ExactInstructionsFunctionHasher {
    /// Singleton instance.
    pub const INSTANCE: ExactInstructionsFunctionHasher = ExactInstructionsFunctionHasher;
}

impl FunctionHasher for ExactInstructionsFunctionHasher {
    fn hash(&self, instruction_bytes: &[u8]) -> u64 {
        fnv1a64(instruction_bytes)
    }

    fn common_bit_count(&self, func_a: &[u8], func_b: &[u8]) -> usize {
        let mut count = 0;
        let min_len = func_a.len().min(func_b.len());
        for i in 0..min_len {
            count += (func_a[i] ^ func_b[i]).count_zeros() as usize;
        }
        count
    }
}

/// Hasher that computes an FNV-1a 64-bit hash over the mnemonic strings
/// of instructions in a function.
///
/// This produces hashes that match when two functions have the same
/// sequence of instruction mnemonics, regardless of operands.
#[derive(Debug, Clone)]
pub struct ExactMnemonicsFunctionHasher;

impl ExactMnemonicsFunctionHasher {
    /// Singleton instance.
    pub const INSTANCE: ExactMnemonicsFunctionHasher = ExactMnemonicsFunctionHasher;
}

impl FunctionHasher for ExactMnemonicsFunctionHasher {
    fn hash(&self, mnemonic_bytes: &[u8]) -> u64 {
        fnv1a64(mnemonic_bytes)
    }

    fn common_bit_count(&self, func_a: &[u8], func_b: &[u8]) -> usize {
        // For mnemonics, exact match means all bits are common
        if func_a == func_b {
            func_a.len() * 8
        } else {
            0
        }
    }
}

/// Compute FNV-1a 64-bit hash.
pub fn fnv1a64(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// A single match between two programs.
///
/// Tracks the addresses in both programs that correspond to each other.
#[derive(Debug, Clone)]
pub struct Match {
    /// Start address of the match in "this" program.
    pub this_beginning: u64,
    /// Start address of the match in "the other" program.
    pub other_beginning: u64,
    /// Objects making up the match in "this" program.
    pub this_match: Vec<MatchItem>,
    /// Objects making up the match in "the other" program.
    pub other_match: Vec<MatchItem>,
    /// Total byte length of the match.
    pub total_length: usize,
}

impl Match {
    /// Create a new byte-based match.
    pub fn from_bytes(this_beginning: u64, other_beginning: u64, bytes: &[u8]) -> Self {
        let this_match: Vec<MatchItem> = bytes
            .iter()
            .map(|b| MatchItem::Byte(*b))
            .collect();
        let total_length = bytes.len();
        Self {
            this_beginning,
            other_beginning,
            this_match: this_match.clone(),
            other_match: this_match,
            total_length,
        }
    }

    /// Create a new code-unit-based match.
    pub fn from_code_units(
        this_beginning: u64,
        other_beginning: u64,
        this_units: Vec<MatchItem>,
        other_units: Vec<MatchItem>,
        total_length: usize,
    ) -> Self {
        Self {
            this_beginning,
            other_beginning,
            this_match: this_units,
            other_match: other_units,
            total_length,
        }
    }

    /// Continue the match with an additional byte.
    pub fn continue_byte(&mut self, byte: u8) {
        self.this_match.push(MatchItem::Byte(byte));
        self.other_match.push(MatchItem::Byte(byte));
        self.total_length += 1;
    }

    /// Continue the match with additional code units.
    pub fn continue_code_units(&mut self, this_unit: MatchItem, other_unit: MatchItem, length: usize) {
        self.this_match.push(this_unit);
        self.other_match.push(other_unit);
        self.total_length += length;
    }

    /// The number of items in the match.
    pub fn length(&self) -> usize {
        self.this_match.len()
    }
}

impl PartialEq for Match {
    fn eq(&self, other: &Self) -> bool {
        self.this_beginning == other.this_beginning
            && self.other_beginning == other.other_beginning
            && self.total_length == other.total_length
    }
}

impl Eq for Match {}

impl PartialOrd for Match {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Match {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.this_beginning
            .cmp(&other.this_beginning)
            .then_with(|| self.other_beginning.cmp(&other.other_beginning))
            .then_with(|| self.length().cmp(&other.length()))
    }
}

/// A single item in a match (either a byte or a code unit reference).
#[derive(Debug, Clone)]
pub enum MatchItem {
    /// A single byte value.
    Byte(u8),
    /// A reference to a code unit at an address.
    CodeUnit { address: u64, length: usize },
    /// A mnemonic string from an instruction.
    Mnemonic(String),
}

impl std::fmt::Display for MatchItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MatchItem::Byte(b) => write!(f, "{:02x}", b),
            MatchItem::CodeUnit { address, length } => {
                write!(f, "CU@0x{:x}[{}]", address, length)
            }
            MatchItem::Mnemonic(m) => write!(f, "{}", m),
        }
    }
}

/// A matched pair of functions between two programs.
#[derive(Debug, Clone)]
pub struct MatchedFunctions {
    /// Name/identifier of program A.
    pub a_program: String,
    /// Name/identifier of program B.
    pub b_program: String,
    /// Entry point address in program A.
    pub a_address: u64,
    /// Entry point address in program B.
    pub b_address: u64,
    /// Number of functions in program A that hashed to this value.
    pub a_match_count: usize,
    /// Number of functions in program B that hashed to this value.
    pub b_match_count: usize,
    /// The reason for the match.
    pub reason: String,
}

impl MatchedFunctions {
    /// Whether this is a one-to-one match.
    pub fn is_one_to_one(&self) -> bool {
        self.a_match_count == 1 && self.b_match_count == 1
    }

    /// Whether this is a one-to-many or many-to-many match.
    pub fn is_non_one_to_one(&self) -> bool {
        !self.is_one_to_one()
    }
}

/// Match a set of functions from program A against program B using function hashing.
///
/// Returns all unique matches where functions in both programs hash to the same value.
///
/// # Arguments
/// * `a_hashes` - Map of entry_point -> function_bytes for program A
/// * `b_hashes` - Map of entry_point -> function_bytes for program B
/// * `hasher` - The function hasher to use
/// * `include_one_to_one` - Whether to include one-to-one matches
/// * `include_non_one_to_one` - Whether to include one-to-many/many-to-many matches
pub fn match_functions(
    a_program: &str,
    a_functions: &[(u64, Vec<u8>)],
    b_program: &str,
    b_functions: &[(u64, Vec<u8>)],
    hasher: &dyn FunctionHasher,
    include_one_to_one: bool,
    include_non_one_to_one: bool,
) -> Vec<MatchedFunctions> {
    // Hash all functions in program A
    let mut hash_map: HashMap<u64, (Vec<u64>, Vec<u64>)> = HashMap::new();

    for (addr, bytes) in a_functions {
        let hash = hasher.hash(bytes);
        let entry = hash_map.entry(hash).or_default();
        entry.0.push(*addr);
    }

    // Hash all functions in program B
    for (addr, bytes) in b_functions {
        let hash = hasher.hash(bytes);
        let entry = hash_map.entry(hash).or_default();
        entry.1.push(*addr);
    }

    // Generate matches
    let mut results = Vec::new();
    for (_, (a_addrs, b_addrs)) in &hash_map {
        let is_one_to_one = a_addrs.len() == 1 && b_addrs.len() == 1;

        if (include_one_to_one && is_one_to_one)
            || (include_non_one_to_one && !is_one_to_one)
        {
            for &a_addr in a_addrs {
                for &b_addr in b_addrs {
                    results.push(MatchedFunctions {
                        a_program: a_program.to_string(),
                        b_program: b_program.to_string(),
                        a_address: a_addr,
                        b_address: b_addr,
                        a_match_count: a_addrs.len(),
                        b_match_count: b_addrs.len(),
                        reason: "Code Only Match".to_string(),
                    });
                }
            }
        }
    }

    results
}

/// A set of subroutine matches between two programs.
#[derive(Debug, Clone)]
pub struct FunctionMatchSet {
    /// Name of program A.
    pub a_program: String,
    /// Name of program B.
    pub b_program: String,
    /// The matches found.
    pub matches: Vec<SubroutineMatch>,
}

impl FunctionMatchSet {
    /// Create a new empty match set.
    pub fn new(a_program: &str, b_program: &str) -> Self {
        Self {
            a_program: a_program.to_string(),
            b_program: b_program.to_string(),
            matches: Vec::new(),
        }
    }

    /// Add a match to the set.
    pub fn add_match(&mut self, m: SubroutineMatch) {
        self.matches.push(m);
    }

    /// Sort the matches by address.
    pub fn sort(&mut self) {
        self.matches.sort_by_key(|m| m.a_address);
    }
}

/// A subroutine match between two programs.
#[derive(Debug, Clone)]
pub struct SubroutineMatch {
    /// Entry point in program A.
    pub a_address: u64,
    /// Entry point in program B.
    pub b_address: u64,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
    /// The match reason/description.
    pub reason: String,
}

/// A set of byte data matches between two programs.
#[derive(Debug, Clone)]
pub struct MatchDataSet {
    /// Name of program A.
    pub a_program: String,
    /// Name of program B.
    pub b_program: String,
    /// The matches found.
    pub matches: Vec<MatchedData>,
}

/// A single data match between two programs.
#[derive(Debug, Clone)]
pub struct MatchedData {
    /// Address in program A.
    pub a_address: u64,
    /// Address in program B.
    pub b_address: u64,
    /// Length of the matching data in bytes.
    pub length: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fnv1a64_empty() {
        let hash = fnv1a64(&[]);
        assert_eq!(hash, 0xcbf29ce484222325);
    }

    #[test]
    fn test_fnv1a64_known() {
        // FNV-1a hash of "foobar" should be deterministic
        let hash = fnv1a64(b"foobar");
        assert_ne!(hash, 0);
        // Same input should produce same hash
        assert_eq!(hash, fnv1a64(b"foobar"));
        // Different input should produce different hash
        assert_ne!(hash, fnv1a64(b"foobaz"));
    }

    #[test]
    fn test_exact_bytes_hasher() {
        let hasher = ExactBytesFunctionHasher;
        let h1 = hasher.hash(&[0x48, 0x89, 0xE5]);
        let h2 = hasher.hash(&[0x48, 0x89, 0xE5]);
        let h3 = hasher.hash(&[0x48, 0x89, 0xE6]);
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_exact_bytes_common_bits() {
        let hasher = ExactBytesFunctionHasher;
        assert_eq!(hasher.common_bit_count(&[0xFF; 10], &[0x00; 10]), 80);
    }

    #[test]
    fn test_exact_instructions_hasher() {
        let hasher = ExactInstructionsFunctionHasher;
        let h1 = hasher.hash(&[0x48, 0x89, 0xE5]);
        let h2 = hasher.hash(&[0x48, 0x89, 0xE6]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_exact_instructions_common_bits() {
        let hasher = ExactInstructionsFunctionHasher;
        // 0xFF ^ 0xFF = 0x00, ~0x00 = 0xFF, bit_count(0xFF) = 8
        assert_eq!(hasher.common_bit_count(&[0xFF; 3], &[0xFF; 3]), 24);
        // 0xFF ^ 0x00 = 0xFF, ~0xFF = 0x00, bit_count(0x00) = 0
        assert_eq!(hasher.common_bit_count(&[0xFF; 3], &[0x00; 3]), 0);
    }

    #[test]
    fn test_exact_mnemonics_hasher() {
        let hasher = ExactMnemonicsFunctionHasher;
        let h1 = hasher.hash(b"push\nrbp\nmov\nrsp\n");
        let h2 = hasher.hash(b"push\nrbp\nmov\nrsp\n");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_match_from_bytes() {
        let m = Match::from_bytes(0x1000, 0x2000, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(m.this_beginning, 0x1000);
        assert_eq!(m.other_beginning, 0x2000);
        assert_eq!(m.length(), 3);
        assert_eq!(m.total_length, 3);
    }

    #[test]
    fn test_match_ordering() {
        let m1 = Match::from_bytes(0x1000, 0x2000, &[0xAA]);
        let m2 = Match::from_bytes(0x1000, 0x3000, &[0xAA]);
        assert!(m1 < m2);
    }

    #[test]
    fn test_match_continue() {
        let mut m = Match::from_bytes(0x1000, 0x2000, &[0xAA]);
        m.continue_byte(0xBB);
        assert_eq!(m.length(), 2);
        assert_eq!(m.total_length, 2);
    }

    #[test]
    fn test_matched_functions() {
        let mf = MatchedFunctions {
            a_program: "prog_a".into(),
            b_program: "prog_b".into(),
            a_address: 0x1000,
            b_address: 0x2000,
            a_match_count: 1,
            b_match_count: 1,
            reason: "Code Only Match".into(),
        };
        assert!(mf.is_one_to_one());
        assert!(!mf.is_non_one_to_one());
    }

    #[test]
    fn test_match_functions() {
        let hasher = ExactBytesFunctionHasher;
        let a_funcs = vec![(0x1000, vec![0xAA, 0xBB]), (0x1100, vec![0xCC, 0xDD])];
        let b_funcs = vec![(0x2000, vec![0xAA, 0xBB]), (0x2100, vec![0xEE, 0xFF])];

        let matches = match_functions("A", &a_funcs, "B", &b_funcs, &hasher, true, false);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].a_address, 0x1000);
        assert_eq!(matches[0].b_address, 0x2000);
    }

    #[test]
    fn test_match_functions_no_matches() {
        let hasher = ExactBytesFunctionHasher;
        let a_funcs = vec![(0x1000, vec![0xAA])];
        let b_funcs = vec![(0x2000, vec![0xBB])];

        let matches = match_functions("A", &a_funcs, "B", &b_funcs, &hasher, true, true);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_function_match_set() {
        let mut set = FunctionMatchSet::new("A", "B");
        set.add_match(SubroutineMatch {
            a_address: 0x2000,
            b_address: 0x3000,
            confidence: 1.0,
            reason: "exact".into(),
        });
        set.add_match(SubroutineMatch {
            a_address: 0x1000,
            b_address: 0x2000,
            confidence: 0.9,
            reason: "similar".into(),
        });
        set.sort();
        assert_eq!(set.matches[0].a_address, 0x1000);
        assert_eq!(set.matches[1].a_address, 0x2000);
    }

    #[test]
    fn test_match_item_display() {
        assert_eq!(MatchItem::Byte(0xAB).to_string(), "ab");
        assert_eq!(
            MatchItem::CodeUnit {
                address: 0x1000,
                length: 4
            }
            .to_string(),
            "CU@0x1000[4]"
        );
        assert_eq!(MatchItem::Mnemonic("mov".into()).to_string(), "mov");
    }

    #[test]
    fn test_matched_data() {
        let md = MatchedData {
            a_address: 0x1000,
            b_address: 0x2000,
            length: 64,
        };
        assert_eq!(md.length, 64);
    }
}
