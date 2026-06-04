//! Entropy analysis for memory blocks.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.entropy.EntropyCalculate`.
//!
//! Calculates Shannon entropy over fixed-size chunks of a memory block.
//! Entropy values are quantized to 0..255 for efficient display in an
//! entropy overview panel.
//!
//! # Usage
//!
//! ```rust
//! use ghidra_features::base::entropy::EntropyCalculator;
//!
//! let data: Vec<u8> = (0..=255).collect(); // 256 varied bytes
//! let entropy = EntropyCalculator::new(&data, 256);
//! assert_eq!(entropy.num_chunks(), 1);
//! // All different bytes -> high quantized entropy.
//! assert!(entropy.get_value(0) > 200);
//! ```

use std::collections::HashMap;

/// Default chunk size (bytes) used for entropy analysis.
pub const DEFAULT_CHUNK_SIZE: usize = 256;

/// Maximum number of quantized entropy levels (0..255).
const MAX_ENTROPY_LEVEL: usize = 256;

/// Calculates Shannon entropy over fixed-size chunks of byte data.
///
/// The raw entropy (in bits per byte) is quantized to 0..255 for compact
/// visualization. A value of 0 means all bytes are identical; 255 means
/// maximum randomness.
///
/// Ported from `ghidra.app.plugin.core.entropy.EntropyCalculate`.
pub struct EntropyCalculator {
    /// Quantized entropy values, one per chunk.
    entropy: Vec<i32>,
    /// Chunk size used for the calculation.
    chunk_size: usize,
}

impl EntropyCalculator {
    /// Create a new entropy calculator for the given byte data.
    ///
    /// # Arguments
    ///
    /// * `data` - The raw bytes to analyze.
    /// * `chunk_size` - Number of bytes per entropy chunk. Must be > 0.
    ///
    /// # Panics
    ///
    /// Panics if `chunk_size` is 0.
    pub fn new(data: &[u8], chunk_size: usize) -> Self {
        assert!(chunk_size > 0, "chunk_size must be > 0");
        let entropy = compute_entropy(data, chunk_size);
        Self { entropy, chunk_size }
    }

    /// Create a calculator with the default chunk size (256 bytes).
    pub fn with_default_chunk_size(data: &[u8]) -> Self {
        Self::new(data, DEFAULT_CHUNK_SIZE)
    }

    /// Get the quantized entropy value for a given byte offset.
    ///
    /// Returns -1 if the offset is out of range.
    ///
    /// # Arguments
    ///
    /// * `offset` - Byte offset within the analyzed region.
    pub fn get_value(&self, offset: usize) -> i32 {
        if offset >= self.total_size() {
            return -1;
        }
        let chunk_idx = offset / self.chunk_size;
        if chunk_idx >= self.entropy.len() {
            return -1;
        }
        self.entropy[chunk_idx]
    }

    /// Get the quantized entropy value for a given chunk index.
    ///
    /// Returns -1 if the chunk index is out of range.
    pub fn get_chunk_value(&self, chunk_index: usize) -> i32 {
        self.entropy.get(chunk_index).copied().unwrap_or(-1)
    }

    /// Number of chunks analyzed.
    pub fn num_chunks(&self) -> usize {
        self.entropy.len()
    }

    /// Chunk size used for the calculation.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Total size of the analyzed region in bytes.
    pub fn total_size(&self) -> usize {
        self.entropy.len() * self.chunk_size
    }

    /// Get a reference to the full entropy array.
    pub fn values(&self) -> &[i32] {
        &self.entropy
    }

    /// Find the chunk with the highest entropy.
    ///
    /// Returns `Some((chunk_index, value))` or `None` if no data.
    pub fn max_entropy_chunk(&self) -> Option<(usize, i32)> {
        self.entropy
            .iter()
            .enumerate()
            .filter(|(_, &v)| v >= 0)
            .max_by_key(|(_, &v)| v)
            .map(|(i, &v)| (i, v))
    }

    /// Find the chunk with the lowest entropy.
    ///
    /// Returns `Some((chunk_index, value))` or `None` if no data.
    pub fn min_entropy_chunk(&self) -> Option<(usize, i32)> {
        self.entropy
            .iter()
            .enumerate()
            .filter(|(_, &v)| v >= 0)
            .min_by_key(|(_, &v)| v)
            .map(|(i, &v)| (i, v))
    }

    /// Compute the average entropy across all valid chunks.
    pub fn average_entropy(&self) -> f64 {
        let valid: Vec<i32> = self.entropy.iter().copied().filter(|&v| v >= 0).collect();
        if valid.is_empty() {
            return 0.0;
        }
        valid.iter().sum::<i32>() as f64 / valid.len() as f64
    }
}

/// Compute Shannon entropy for each chunk of the data.
///
/// Returns a vector of quantized entropy values (0..255) for each chunk.
/// Chunks with read errors are represented as -1.
fn compute_entropy(data: &[u8], chunk_size: usize) -> Vec<i32> {
    if data.is_empty() {
        return Vec::new();
    }

    let num_chunks = (data.len() + chunk_size - 1) / chunk_size;
    let mut entropy = Vec::with_capacity(num_chunks);

    // Pre-compute log table for efficiency (port of buildLogTable in Java).
    let log_table = build_log_table(chunk_size);

    for chunk_idx in 0..num_chunks {
        let start = chunk_idx * chunk_size;
        let end = std::cmp::min(start + chunk_size, data.len());
        let chunk_data = &data[start..end];

        let val = quantize_chunk(chunk_data, &log_table, chunk_size);
        entropy.push(val);
    }

    entropy
}

/// Build a pre-computed log table for entropy calculation.
///
/// For each possible byte count `i` (0..chunk_size), stores:
/// `- (i/chunk_size) * log2(i/chunk_size)`
fn build_log_table(chunk_size: usize) -> Vec<f64> {
    let mut table = vec![0.0; chunk_size + 1];
    let chunk_float = chunk_size as f64;
    let log_two = 2.0_f64.ln();

    for i in 1..chunk_size {
        let prob = i as f64 / chunk_float;
        table[i] = -prob * (prob.ln() / log_two);
    }
    // table[0] = 0.0, table[chunk_size] = 0.0 (already set)
    table
}

/// Build a byte histogram for a chunk of data and compute quantized entropy.
fn quantize_chunk(chunk: &[u8], log_table: &[f64], chunk_size: usize) -> i32 {
    if chunk.is_empty() {
        return -1;
    }

    // Build histogram: count occurrences of each byte value.
    let mut histo = [0u32; 256];
    for &b in chunk {
        histo[b as usize] += 1;
    }

    // Sum up entropy contributions.
    let mut sum = 0.0_f64;
    for &count in &histo {
        if (count as usize) < log_table.len() {
            sum += log_table[count as usize];
        }
    }

    // Normalize to 0..255 range.
    sum = (sum / 8.0) * 256.0;
    let val = sum.floor() as i32;
    std::cmp::min(val, 255)
}

/// Compute the raw Shannon entropy (bits per byte) of a byte slice.
///
/// This is a standalone utility function, not quantized.
///
/// # Returns
///
/// A value between 0.0 (all identical bytes) and 8.0 (maximum randomness).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let len = data.len() as f64;
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let mut entropy = 0.0_f64;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Represents a single entropy data point for a chunk.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EntropyPoint {
    /// Chunk index.
    pub chunk_index: usize,
    /// Start offset of the chunk within the analyzed region.
    pub offset: usize,
    /// Quantized entropy value (0..255), or -1 on error.
    pub value: i32,
    /// Raw entropy (bits per byte).
    pub raw_entropy: f64,
}

/// Build a summary of entropy data for visualization.
pub fn entropy_summary(data: &[u8], chunk_size: usize) -> Vec<EntropyPoint> {
    let log_table = build_log_table(chunk_size);
    let num_chunks = (data.len() + chunk_size - 1) / chunk_size;
    let mut points = Vec::with_capacity(num_chunks);

    for chunk_idx in 0..num_chunks {
        let start = chunk_idx * chunk_size;
        let end = std::cmp::min(start + chunk_size, data.len());
        let chunk_data = &data[start..end];

        let value = quantize_chunk(chunk_data, &log_table, chunk_size);
        let raw_entropy = shannon_entropy(chunk_data);

        points.push(EntropyPoint {
            chunk_index: chunk_idx,
            offset: start,
            value,
            raw_entropy,
        });
    }

    points
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_data() {
        let calc = EntropyCalculator::new(&[], 256);
        assert_eq!(calc.num_chunks(), 0);
        assert_eq!(calc.get_value(0), -1);
    }

    #[test]
    fn test_all_zeros() {
        let data = vec![0u8; 256];
        let calc = EntropyCalculator::new(&data, 256);
        assert_eq!(calc.num_chunks(), 1);
        // All identical bytes = 0 entropy.
        assert_eq!(calc.get_value(0), 0);
    }

    #[test]
    fn test_high_entropy() {
        // A sequence of all different bytes should have high entropy.
        let data: Vec<u8> = (0..=255).collect();
        let calc = EntropyCalculator::new(&data, 256);
        assert_eq!(calc.num_chunks(), 1);
        let val = calc.get_value(0);
        // Should be close to 255 (max quantized entropy).
        assert!(val > 200, "Expected high entropy, got {}", val);
    }

    #[test]
    fn test_mixed_entropy() {
        // First half zeros, second half varied.
        let mut data = vec![0u8; 128];
        data.extend(0..128u8);
        let calc = EntropyCalculator::new(&data, 128);
        assert_eq!(calc.num_chunks(), 2);
        let v0 = calc.get_value(0);
        let v1 = calc.get_value(128);
        assert_eq!(v0, 0); // All zeros = 0 entropy
        assert!(v1 > v0); // Varied bytes = higher entropy
    }

    #[test]
    fn test_out_of_range() {
        let data = vec![0u8; 10];
        let calc = EntropyCalculator::new(&data, 5);
        assert_eq!(calc.get_value(100), -1);
        assert_eq!(calc.get_chunk_value(100), -1);
    }

    #[test]
    fn test_shannon_entropy_uniform() {
        // All same bytes = 0 entropy
        assert_eq!(shannon_entropy(&[0u8; 100]), 0.0);
    }

    #[test]
    fn test_shannon_entropy_two_values() {
        // 50/50 split of 0 and 1 -> entropy = 1.0 bit
        let mut data = vec![0u8; 50];
        data.extend(vec![1u8; 50]);
        let e = shannon_entropy(&data);
        assert!((e - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_max_min_entropy_chunk() {
        let mut data = vec![0u8; 256]; // Low entropy chunk
        data.extend((0..=255).collect::<Vec<u8>>()); // High entropy chunk
        let calc = EntropyCalculator::new(&data, 256);

        let (min_idx, min_val) = calc.min_entropy_chunk().unwrap();
        let (max_idx, max_val) = calc.max_entropy_chunk().unwrap();
        assert_eq!(min_idx, 0);
        assert_eq!(max_idx, 1);
        assert!(min_val < max_val);
    }

    #[test]
    fn test_average_entropy() {
        let data = vec![0u8; 256];
        let calc = EntropyCalculator::new(&data, 256);
        assert_eq!(calc.average_entropy(), 0.0);
    }

    #[test]
    fn test_entropy_summary() {
        let data = vec![0u8; 128];
        let points = entropy_summary(&data, 64);
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].offset, 0);
        assert_eq!(points[1].offset, 64);
    }

    #[test]
    fn test_chunk_size_panic() {
        let result = std::panic::catch_unwind(|| {
            EntropyCalculator::new(&[0u8; 10], 0);
        });
        assert!(result.is_err());
    }
}
