//! LSH Binner -- computes bin IDs for LSH vectors.
//!
//! Ported from `LSHBinner.java` in the BSimElasticPlugin extension.
//!
//! Uses FFT-based random projection to compute 16-wide dot products with a
//! family of random vectors. The random vectors are derived from a seed hash
//! via an FFT on 16-wide basis vectors.

/// A reference to a mutable character buffer used for token storage.
///
/// Each `BytesRef` holds the base64-encoded token characters for one bin ID.
#[derive(Debug, Clone)]
pub struct BytesRef {
    /// The character buffer holding the encoded token.
    pub buffer: Vec<char>,
}

impl BytesRef {
    /// Create a new `BytesRef` with the given capacity.
    pub fn new(size: usize) -> Self {
        Self {
            buffer: vec!['\0'; size],
        }
    }
}

/// A hash entry representing one non-zero coefficient in an LSH vector.
///
/// Each entry has a 32-bit hash (dimension index) and a floating-point
/// coefficient (weight).
#[derive(Debug, Clone, Copy)]
pub struct HashEntry {
    /// The hash / dimension index.
    hash: u32,
    /// The coefficient / weight.
    coeff: f64,
}

impl HashEntry {
    /// Create a new hash entry.
    pub fn new(hash: u32, coeff: f64) -> Self {
        Self { hash, coeff }
    }

    /// Get the hash value.
    pub fn get_hash(self) -> u32 {
        self.hash
    }

    /// Get the coefficient.
    pub fn get_coeff(self) -> f64 {
        self.coeff
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size above which to use FFT to calculate the dot-product family.
const VEC_SIZE_UPPER: usize = 5;

/// Base hash value for generating the random family of vectors.
const LSH_HASHBASE: u32 = 0xd7e6_a299;

/// Linear congruential generator multiplier.
const HASH_MULTIPLIER: u32 = 1_103_515_245;

/// Linear congruential generator addend.
const HASH_ADDEND: u32 = 12345;

/// Base64-lite encoding alphabet (URL-safe, no padding).
const BASE64_ENCODE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// ---------------------------------------------------------------------------
// Static sign table
// ---------------------------------------------------------------------------

use std::sync::LazyLock;

/// Pre-calculated table for generating dot-products with the random family
/// of vectors directly. 512 entries: 32 rows x 16 columns of '+'/'-' signs.
static HASH_SIGN_TABLE: LazyLock<[char; 512]> = LazyLock::new(|| {
    let mut table = ['+'; 512];
    let mut arr = [0i32; 16];

    for i in 0..16 {
        let hibit0ptr = i * 16;
        let hibit1ptr = (i + 16) * 16;

        for j in 0..16 {
            arr[j] = 0;
        }
        arr[i] = 1;
        hash_fft16_i32(&mut arr);

        for j in 0..16 {
            if arr[j] > 0 {
                table[hibit0ptr + j] = '+';
                table[hibit1ptr + j] = '-';
            } else {
                table[hibit0ptr + j] = '-';
                table[hibit1ptr + j] = '+';
            }
        }
    }

    table
});

// ---------------------------------------------------------------------------
// FFT
// ---------------------------------------------------------------------------

/// In-place radix-2 FFT on a 16-element integer array (butterfly operations).
fn hash_fft16_i32(arr: &mut [i32; 16]) {
    // Stage 1: stride 8
    for i in 0..8 {
        let x = arr[i];
        let y = arr[i + 8];
        arr[i] = x + y;
        arr[i + 8] = x - y;
    }
    // Stage 2: stride 4
    for base in [0, 8] {
        for i in 0..4 {
            let x = arr[base + i];
            let y = arr[base + i + 4];
            arr[base + i] = x + y;
            arr[base + i + 4] = x - y;
        }
    }
    // Stage 3: stride 2
    for base in [0, 4, 8, 12] {
        for i in 0..2 {
            let x = arr[base + i];
            let y = arr[base + i + 2];
            arr[base + i] = x + y;
            arr[base + i + 2] = x - y;
        }
    }
    // Stage 4: stride 1
    for base in [0, 2, 4, 6, 8, 10, 12, 14] {
        let x = arr[base];
        let y = arr[base + 1];
        arr[base] = x + y;
        arr[base + 1] = x - y;
    }
}

/// In-place radix-2 FFT on a 16-element f64 array (butterfly operations).
fn hash_fft16_f64(arr: &mut [f64; 16]) {
    // Stage 1: stride 8
    for i in 0..8 {
        let x = arr[i];
        let y = arr[i + 8];
        arr[i] = x + y;
        arr[i + 8] = x - y;
    }
    // Stage 2: stride 4
    for base in [0, 8] {
        for i in 0..4 {
            let x = arr[base + i];
            let y = arr[base + i + 4];
            arr[base + i] = x + y;
            arr[base + i + 4] = x - y;
        }
    }
    // Stage 3: stride 2
    for base in [0, 4, 8, 12] {
        for i in 0..2 {
            let x = arr[base + i];
            let y = arr[base + i + 2];
            arr[base + i] = x + y;
            arr[base + i + 2] = x - y;
        }
    }
    // Stage 4: stride 1
    for base in [0, 2, 4, 6, 8, 10, 12, 14] {
        let x = arr[base];
        let y = arr[base + 1];
        arr[base] = x + y;
        arr[base + 1] = x - y;
    }
}

// ---------------------------------------------------------------------------
// LshBinner
// ---------------------------------------------------------------------------

/// Calculates bin IDs for LSH vectors as part of the LSH indexing process.
///
/// The binner uses a family of random vectors derived via FFT from a seed
/// hash to compute dot products. The sign of each dot product becomes one
/// bit in the resulting bin ID.
///
/// # Parameters
///
/// * `k` -- number of bits per bin ID
/// * `L` -- number of independent binnings (hash tables)
#[derive(Debug)]
pub struct LshBinner {
    /// Number of bits per bin id.
    k: i32,
    /// Number of binnings (hash tables).
    l: i32,
    /// Scratch space for dot-product calculation.
    double_buffer: [f64; 16],
    /// Final token list for the tokenizer.
    token_list: Vec<BytesRef>,
}

impl LshBinner {
    /// Create a new uninitialized LSH binner.
    pub fn new() -> Self {
        Self {
            k: -1,
            l: -1,
            double_buffer: [0.0; 16],
            token_list: Vec::new(),
        }
    }

    /// Configure the binner with `k` bits per bin and `L` tables.
    ///
    /// This pre-allocates the token list buffers.
    pub fn set_k_and_l(&mut self, k: i32, l: i32) {
        self.k = k;
        self.l = l;
        let mut num_bits = 1i32;
        while (1 << num_bits) <= l {
            num_bits += 1;
        }
        num_bits += k;
        let mut num_char = num_bits / 6;
        if num_bits % 6 != 0 {
            num_char += 1;
        }
        self.token_list = (0..l)
            .map(|_| BytesRef::new(num_char as usize))
            .collect();
    }

    /// Get a reference to the token list (the bin IDs after calling
    /// [`generate_bin_ids`]).
    pub fn token_list(&self) -> &[BytesRef] {
        &self.token_list
    }

    /// Generate a dot product of the hash vector in `vec` with a random
    /// family of 16 vectors.
    ///
    /// Returns the accumulated bucket with new dot-product bits.
    fn hash16_dot_product(
        &mut self,
        bucket: u32,
        vec: &[HashEntry],
        hashcur: u32,
    ) -> u32 {
        for i in 0..16 {
            self.double_buffer[i] = 0.0;
        }

        if vec.len() < VEC_SIZE_UPPER {
            // Small number of non-zero coefficients: compute directly
            for entry in vec {
                let mut row_num = entry.get_hash() ^ hashcur;
                row_num = row_num.wrapping_mul(HASH_MULTIPLIER).wrapping_add(HASH_ADDEND);
                row_num = (row_num >> 24) & 0x1f;
                let sign_ptr = (row_num as usize) * 16;
                for j in 0..16 {
                    if HASH_SIGN_TABLE[sign_ptr + j] == '+' {
                        self.double_buffer[j] += entry.get_coeff();
                    } else {
                        self.double_buffer[j] -= entry.get_coeff();
                    }
                }
            }
        } else {
            // Many non-zero coefficients: use FFT
            for entry in vec {
                let mut row_num = entry.get_hash() ^ hashcur;
                row_num = row_num.wrapping_mul(HASH_MULTIPLIER).wrapping_add(HASH_ADDEND);
                row_num = (row_num >> 24) & 0x1f;
                if row_num < 0x10 {
                    self.double_buffer[row_num as usize] += entry.get_coeff();
                } else {
                    self.double_buffer[(row_num & 0xf) as usize] -= entry.get_coeff();
                }
            }
            hash_fft16_f64(&mut self.double_buffer);
        }

        // Convert dot-product results to a bit-vector
        let mut result = bucket;
        for i in 0..16 {
            result <<= 1;
            if self.double_buffer[i] > 0.0 {
                result |= 1;
            }
        }
        result
    }

    /// Generate bin IDs for the given hash vector.
    ///
    /// After calling this method, the [`token_list()`](Self::token_list) will
    /// contain the base64-encoded bin IDs for each of the `L` tables.
    pub fn generate_bin_ids(&mut self, vec: &[HashEntry]) {
        let mut bucket: u32 = 0;
        let mut bucket_cnt: u32 = 0;
        let mut hashbase = LSH_HASHBASE;

        for i in 0..self.l {
            let mut curid: u32 = i as u32;
            let mut bitsleft = self.k as u32;

            loop {
                if bucket_cnt == 0 {
                    hashbase = hashbase.wrapping_mul(HASH_MULTIPLIER).wrapping_add(HASH_ADDEND);
                    bucket = self.hash16_dot_product(bucket, vec, hashbase);
                    bucket_cnt = 16;
                }
                if bucket_cnt >= bitsleft {
                    curid <<= bitsleft;
                    let mask = (1u32 << bitsleft) - 1;
                    let val = bucket >> (bucket_cnt - bitsleft);
                    curid |= val & mask;
                    bucket_cnt -= bitsleft;
                    bitsleft = 0;
                } else {
                    curid <<= bucket_cnt;
                    let mask = (1u32 << bucket_cnt) - 1;
                    curid |= bucket & mask;
                    bitsleft -= bucket_cnt;
                    bucket_cnt = 0;
                }
                if bitsleft == 0 {
                    break;
                }
            }

            // Encode to base64-lite
            let token = &mut self.token_list[i as usize].buffer;
            for ch in token.iter_mut() {
                *ch = BASE64_ENCODE[(curid & 0x3f) as usize] as char;
                curid >>= 6;
            }
        }
    }
}

impl Default for LshBinner {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_ref_creation() {
        let br = BytesRef::new(5);
        assert_eq!(br.buffer.len(), 5);
        assert!(br.buffer.iter().all(|&c| c == '\0'));
    }

    #[test]
    fn test_hash_entry_accessors() {
        let he = HashEntry::new(42, 1.5);
        assert_eq!(he.get_hash(), 42);
        assert!((he.get_coeff() - 1.5).abs() < 1e-10);
    }

    #[test]
    fn test_lsh_binner_default() {
        let binner = LshBinner::new();
        assert_eq!(binner.k, -1);
        assert_eq!(binner.l, -1);
        assert!(binner.token_list().is_empty());
    }

    #[test]
    fn test_set_k_and_l() {
        let mut binner = LshBinner::new();
        binner.set_k_and_l(4, 8);
        assert_eq!(binner.k, 4);
        assert_eq!(binner.l, 8);
        assert_eq!(binner.token_list().len(), 8);
        // Each token should have a consistent size
        let token_size = binner.token_list()[0].buffer.len();
        assert!(token_size > 0);
    }

    #[test]
    fn test_generate_bin_ids_produces_tokens() {
        let mut binner = LshBinner::new();
        binner.set_k_and_l(4, 4);

        let vec = vec![
            HashEntry::new(100, 1.0),
            HashEntry::new(200, -0.5),
            HashEntry::new(300, 2.0),
        ];

        binner.generate_bin_ids(&vec);

        // Each token should have been written (no null chars)
        for token in binner.token_list() {
            for &ch in &token.buffer {
                assert!(ch != '\0', "token should be fully filled");
                assert!(
                    BASE64_ENCODE.contains(&(ch as u8)),
                    "token char should be valid base64-lite: {ch}"
                );
            }
        }
    }

    #[test]
    fn test_generate_bin_ids_deterministic() {
        let vec = vec![
            HashEntry::new(100, 1.0),
            HashEntry::new(200, -0.5),
        ];

        let mut binner1 = LshBinner::new();
        binner1.set_k_and_l(4, 4);
        binner1.generate_bin_ids(&vec);

        let mut binner2 = LshBinner::new();
        binner2.set_k_and_l(4, 4);
        binner2.generate_bin_ids(&vec);

        for (t1, t2) in binner1
            .token_list()
            .iter()
            .zip(binner2.token_list().iter())
        {
            assert_eq!(t1.buffer, t2.buffer);
        }
    }

    #[test]
    fn test_fft_i32_identity_on_constant() {
        let mut arr = [1i32; 16];
        hash_fft16_i32(&mut arr);
        // FFT of constant [1,1,...,1] -> [16,0,0,...,0]
        assert_eq!(arr[0], 16);
        for i in 1..16 {
            assert_eq!(arr[i], 0);
        }
    }

    #[test]
    fn test_fft_f64_matches_i32() {
        let mut arr_i32 = [0i32; 16];
        let mut arr_f64 = [0.0f64; 16];
        arr_i32[3] = 1;
        arr_f64[3] = 1.0;

        hash_fft16_i32(&mut arr_i32);
        hash_fft16_f64(&mut arr_f64);

        for i in 0..16 {
            assert!(
                (arr_f64[i] - arr_i32[i] as f64).abs() < 1e-10,
                "FFT mismatch at index {i}: i32={}, f64={}",
                arr_i32[i],
                arr_f64[i]
            );
        }
    }

    #[test]
    fn test_hash_sign_table_populated() {
        // The table should be populated via LazyLock.
        // Just verify some entries exist.
        let table = &*HASH_SIGN_TABLE;
        assert!(table.len() == 512);
        // All entries should be '+' or '-'
        for (i, &c) in table.iter().enumerate() {
            assert!(
                c == '+' || c == '-',
                "Invalid sign at index {i}: {c}"
            );
        }
    }

    #[test]
    fn test_large_vector_uses_fft_path() {
        let mut binner = LshBinner::new();
        binner.set_k_and_l(4, 4);

        // Create a vector with >= VEC_SIZE_UPPER entries to trigger FFT path
        let vec: Vec<HashEntry> = (0..10)
            .map(|i| HashEntry::new(i * 100, 1.0 - (i as f64) * 0.1))
            .collect();

        binner.generate_bin_ids(&vec);
        assert_eq!(binner.token_list().len(), 4);
    }

    #[test]
    fn test_base64_encode_table() {
        assert_eq!(BASE64_ENCODE[0], b'A');
        assert_eq!(BASE64_ENCODE[25], b'Z');
        assert_eq!(BASE64_ENCODE[26], b'a');
        assert_eq!(BASE64_ENCODE[51], b'z');
        assert_eq!(BASE64_ENCODE[62], b'-');
        assert_eq!(BASE64_ENCODE[63], b'_');
    }
}
