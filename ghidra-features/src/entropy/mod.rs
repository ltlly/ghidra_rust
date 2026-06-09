//! Entropy Analysis Plugin -- ported from `EntropyCalculate.java`,
//! `EntropyOverviewColorService.java`, and `EntropyFieldFactory.java`.
//!
//! Computes per-chunk Shannon entropy for a memory region.  Each chunk's
//! byte-value histogram is converted to a normalised entropy score in the
//! range `[0, 255]`, which can drive heat-map visualisations of packed vs
//! unpacked regions.
//!
//! # Sub-modules
//!
//! - [`plugin`] -- Entropy plugin with configurable options, computation,
//!   and address-to-entropy querying.
//! - [`renderer`] -- Listing field renderer that produces colour-coded
//!   entropy display strings.
//!
//! # Example
//!
//! ```
//! use ghidra_features::entropy::EntropyCalculator;
//!
//! let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
//! let calc = EntropyCalculator::from_bytes(&data, 256);
//! assert!(calc.num_chunks() > 0);
//! let v = calc.value_at_offset(0);
//! assert!(v >= 0);
//! ```

pub mod entropy_plugin;
pub mod entropy_renderer;

// ---------------------------------------------------------------------------
// EntropyCalculator
// ---------------------------------------------------------------------------

/// Calculates per-chunk Shannon entropy over a byte buffer.
///
/// Ported from `ghidra.app.plugin.core.entropy.EntropyCalculate`.
///
/// Internally builds a 256-bin histogram per chunk, uses a pre-computed
/// log table for speed, then quantises the raw entropy `H / 8.0 * 256.0`
/// into `0..=255`.
#[derive(Debug, Clone)]
pub struct EntropyCalculator {
    /// Per-chunk quantised entropy. `-1` means the chunk could not be read.
    entropy: Vec<i32>,
    /// Chunk size in bytes.
    chunk_size: usize,
}

impl EntropyCalculator {
    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    /// Build an entropy calculator from a raw byte slice.
    ///
    /// The slice is conceptually the contents of a single memory block.
    pub fn from_bytes(data: &[u8], chunk_size: usize) -> Self {
        assert!(chunk_size > 0, "chunk_size must be > 0");

        let size = data.len();
        let num_chunks = (size + chunk_size - 1) / chunk_size; // ceil-div
        let mut entropy = vec![0i32; num_chunks];

        // Pre-compute log table: logtable[n] = -(n/c) * log2(n/c)  for n in 0..=c
        let log_table = build_log_table(chunk_size);
        let mut histo = [0u32; 256];

        for (chunk_idx, chunk_data) in data.chunks(chunk_size).enumerate() {
            // Build histogram
            histo.fill(0);
            for &b in chunk_data {
                histo[b as usize] += 1;
            }
            // Quantise
            entropy[chunk_idx] = quantize_chunk(&histo, &log_table, chunk_size);
        }

        Self { entropy, chunk_size }
    }

    /// Build an entropy calculator from an iterable of `(offset, byte)`
    /// pairs, simulating sparse memory reads where missing regions get
    /// a sentinel value of `-1`.
    ///
    /// This mirrors the Java version's `MemoryAccessException` path.
    pub fn from_sparse<I>(iter: I, block_size: usize, chunk_size: usize) -> Self
    where
        I: IntoIterator<Item = (usize, u8)>,
    {
        assert!(chunk_size > 0, "chunk_size must be > 0");

        let num_chunks = (block_size + chunk_size - 1) / chunk_size;
        let mut entropy = vec![-1i32; num_chunks]; // default: undefined
        let log_table = build_log_table(chunk_size);

        // Collect bytes into a temporary dense buffer
        let mut buf = vec![0u8; block_size];
        let mut present = vec![false; block_size];
        for (off, byte) in iter {
            if off < block_size {
                buf[off] = byte;
                present[off] = true;
            }
        }

        let mut histo = [0u32; 256];
        for (chunk_idx, (chunk_bytes, chunk_present)) in
            buf.chunks(chunk_size).zip(present.chunks(chunk_size)).enumerate()
        {
            if !chunk_present.iter().all(|&p| p) {
                // At least one byte missing -> undefined
                entropy[chunk_idx] = -1;
                continue;
            }
            histo.fill(0);
            for &b in chunk_bytes {
                histo[b as usize] += 1;
            }
            entropy[chunk_idx] = quantize_chunk(&histo, &log_table, chunk_size);
        }

        Self { entropy, chunk_size }
    }

    // ------------------------------------------------------------------
    // Query
    // ------------------------------------------------------------------

    /// Return the quantised entropy value at the given *byte* offset.
    ///
    /// Returns `-1` for out-of-range or undefined chunks.
    pub fn value_at_offset(&self, offset: usize) -> i32 {
        let chunk_idx = offset / self.chunk_size;
        match self.entropy.get(chunk_idx) {
            Some(&v) => v,
            None => -1,
        }
    }

    /// Return the quantised entropy value for a specific chunk index.
    ///
    /// Returns `-1` for out-of-range indices.
    pub fn value_at_chunk(&self, chunk_idx: usize) -> i32 {
        match self.entropy.get(chunk_idx) {
            Some(&v) => v,
            None => -1,
        }
    }

    /// Return the number of chunks.
    pub fn num_chunks(&self) -> usize {
        self.entropy.len()
    }

    /// Return the chunk size in bytes.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Return the raw entropy slice (per-chunk quantised values).
    pub fn as_slice(&self) -> &[i32] {
        &self.entropy
    }

    /// Return the minimum non-negative entropy value, or `-1` if none.
    pub fn min_entropy(&self) -> i32 {
        self.entropy
            .iter()
            .copied()
            .filter(|&v| v >= 0)
            .min()
            .unwrap_or(-1)
    }

    /// Return the maximum entropy value, or `-1` if none.
    pub fn max_entropy(&self) -> i32 {
        self.entropy
            .iter()
            .copied()
            .filter(|&v| v >= 0)
            .max()
            .unwrap_or(-1)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build a pre-computed log table for chunk entropy.
///
/// `logtable[n] = -(n / chunk_size) * log2(n / chunk_size)` for `n` in
/// `0..=chunk_size`.  The two edge cases (`n == 0` and `n == chunk_size`)
/// are both mapped to `0.0`.
fn build_log_table(chunk_size: usize) -> Vec<f64> {
    let mut table = vec![0.0f64; chunk_size + 1];
    let c = chunk_size as f64;
    let ln2 = core::f64::consts::LN_2;
    for i in 1..chunk_size {
        let prob = i as f64 / c;
        table[i] = -prob * (prob.ln() / ln2);
    }
    // table[0] and table[chunk_size] already 0.0
    table
}

/// Quantize a histogram chunk into a `0..=255` entropy value.
fn quantize_chunk(histo: &[u32; 256], log_table: &[f64], _chunk_size: usize) -> i32 {
    let mut sum = 0.0f64;
    for &count in histo.iter() {
        sum += log_table[count as usize];
    }
    // Normalise: full entropy for 256 uniform bins = 8.0 bits.
    // Multiply by 256 to get the quantised value.
    let val = (sum / 8.0) * 256.0;
    let val = val.floor() as i32;
    val.min(255).max(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uniform_distribution() {
        // 256 bytes, each value exactly once -> maximum entropy
        let data: Vec<u8> = (0u8..=255).collect();
        let calc = EntropyCalculator::from_bytes(&data, 256);
        assert_eq!(calc.num_chunks(), 1);
        // Full entropy: sum = 8.0, val = floor(8.0/8.0 * 256.0) = 255
        assert_eq!(calc.value_at_offset(0), 255);
    }

    #[test]
    fn test_zero_entropy() {
        // All same bytes -> zero entropy
        let data = vec![0xAAu8; 256];
        let calc = EntropyCalculator::from_bytes(&data, 256);
        assert_eq!(calc.num_chunks(), 1);
        assert_eq!(calc.value_at_offset(0), 0);
    }

    #[test]
    fn test_single_byte_chunk() {
        // Chunk size 1: always zero entropy (only one byte per chunk)
        let data = vec![0x00, 0xFF, 0x42, 0x80];
        let calc = EntropyCalculator::from_bytes(&data, 1);
        assert_eq!(calc.num_chunks(), 4);
        for i in 0..4 {
            assert_eq!(calc.value_at_chunk(i), 0);
        }
    }

    #[test]
    fn test_multiple_chunks() {
        let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let calc = EntropyCalculator::from_bytes(&data, 256);
        assert_eq!(calc.num_chunks(), 4);
        // Each chunk has all 256 values -> max entropy
        for i in 0..4 {
            assert_eq!(calc.value_at_chunk(i), 255);
        }
    }

    #[test]
    fn test_partial_last_chunk() {
        // 300 bytes with chunk_size 256 -> 2 chunks, second has 44 bytes
        let data: Vec<u8> = (0..300).map(|i| (i % 256) as u8).collect();
        let calc = EntropyCalculator::from_bytes(&data, 256);
        assert_eq!(calc.num_chunks(), 2);
        assert_eq!(calc.value_at_chunk(0), 255); // full uniform chunk
        // second chunk has 44 bytes, less than full -> different entropy
        let v1 = calc.value_at_chunk(1);
        assert!(v1 >= 0 && v1 <= 255);
    }

    #[test]
    fn test_out_of_range_returns_negative() {
        let data = vec![0u8; 100];
        let calc = EntropyCalculator::from_bytes(&data, 50);
        assert_eq!(calc.num_chunks(), 2);
        assert_eq!(calc.value_at_offset(999), -1);
        assert_eq!(calc.value_at_chunk(999), -1);
    }

    #[test]
    fn test_empty_data() {
        let data: Vec<u8> = vec![];
        let calc = EntropyCalculator::from_bytes(&data, 256);
        assert_eq!(calc.num_chunks(), 0);
        assert_eq!(calc.value_at_offset(0), -1);
    }

    #[test]
    fn test_min_max_entropy() {
        // First chunk: zero entropy (all same byte). Second chunk: maximum entropy.
        let mut data = vec![0x00u8; 128];
        // 128 bytes with all 256 values: 128 distinct values = 7 bits entropy
        data.extend((0..128).map(|i| i as u8));
        let calc = EntropyCalculator::from_bytes(&data, 128);
        assert_eq!(calc.num_chunks(), 2);
        assert_eq!(calc.min_entropy(), 0);
        // Second chunk has 128 distinct values in 128 slots: H = 7.0 bits
        // quantised = floor(7.0/8.0 * 256) = 224
        assert_eq!(calc.max_entropy(), 224);
    }

    #[test]
    fn test_sparse_undefined() {
        // Only provide 1 byte out of 10 -> undefined chunk
        let iter = vec![(5usize, 0x42u8)];
        let calc = EntropyCalculator::from_sparse(iter, 10, 10);
        assert_eq!(calc.num_chunks(), 1);
        // Chunk has missing bytes -> -1
        assert_eq!(calc.value_at_chunk(0), -1);
    }

    #[test]
    fn test_sparse_complete() {
        // Provide all 10 bytes -> complete chunk, zero entropy
        let iter: Vec<(usize, u8)> = (0..10).map(|i| (i, 0xAA)).collect();
        let calc = EntropyCalculator::from_sparse(iter, 10, 10);
        assert_eq!(calc.num_chunks(), 1);
        assert_eq!(calc.value_at_chunk(0), 0);
    }

    #[test]
    fn test_as_slice() {
        let data = vec![0xAAu8; 256];
        let calc = EntropyCalculator::from_bytes(&data, 128);
        let slice = calc.as_slice();
        assert_eq!(slice.len(), 2);
        assert_eq!(slice[0], 0);
        assert_eq!(slice[1], 0);
    }

    #[test]
    fn test_chunk_size_accessor() {
        let data = vec![0u8; 100];
        let calc = EntropyCalculator::from_bytes(&data, 32);
        assert_eq!(calc.chunk_size(), 32);
    }

    #[test]
    fn test_two_value_distribution() {
        // 128 of 0x00 + 128 of 0xFF -> entropy = 1 bit
        // H = -0.5*log2(0.5) - 0.5*log2(0.5) = 1.0
        // quantised = floor(1.0/8.0 * 256.0) = 32
        let mut data = vec![0x00u8; 128];
        data.extend(vec![0xFFu8; 128]);
        let calc = EntropyCalculator::from_bytes(&data, 256);
        assert_eq!(calc.num_chunks(), 1);
        assert_eq!(calc.value_at_offset(0), 32);
    }
}
