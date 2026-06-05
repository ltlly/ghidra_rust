//! Locality-Sensitive Hashing (LSH) for BSim function matching.
//!
//! Ports `ghidra.features.bsim.query.LSHException` and related LSH types.

/// Exception type for LSH operations.
///
/// Ports `ghidra.features.bsim.query.LSHException`.
#[derive(Debug, Clone)]
pub struct LSHException {
    message: String,
}

impl LSHException {
    /// Create a new LSH exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }

    /// Get the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for LSHException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LSH error: {}", self.message)
    }
}

impl std::error::Error for LSHException {}

/// An LSH hash table for function matching.
///
/// Supports min-hash based locality-sensitive hashing for efficiently
/// finding similar functions in a large corpus.
#[derive(Debug, Clone)]
pub struct LshHashTable {
    /// Number of hash functions (bands in banding technique).
    pub num_bands: usize,
    /// Number of rows per band.
    pub rows_per_band: usize,
    /// Hash buckets: bucket_id -> list of function indices.
    pub buckets: std::collections::HashMap<u64, Vec<usize>>,
}

impl LshHashTable {
    /// Create a new LSH hash table.
    pub fn new(num_bands: usize, rows_per_band: usize) -> Self {
        Self {
            num_bands,
            rows_per_band,
            buckets: std::collections::HashMap::new(),
        }
    }

    /// Insert a function's signature hash into the table.
    pub fn insert(&mut self, function_index: usize, signature_hash: &[u64]) {
        for (band_idx, chunk) in signature_hash.chunks(self.rows_per_band).enumerate() {
            let bucket_id = self.compute_band_hash(band_idx, chunk);
            self.buckets.entry(bucket_id).or_default().push(function_index);
        }
    }

    /// Query for candidate matches given a signature hash.
    pub fn query(&self, signature_hash: &[u64]) -> Vec<usize> {
        let mut candidates = std::collections::HashSet::new();
        for (band_idx, chunk) in signature_hash.chunks(self.rows_per_band).enumerate() {
            let bucket_id = self.compute_band_hash(band_idx, chunk);
            if let Some(bucket) = self.buckets.get(&bucket_id) {
                candidates.extend(bucket);
            }
        }
        candidates.into_iter().collect()
    }

    /// Compute the hash for a band.
    fn compute_band_hash(&self, band_idx: usize, chunk: &[u64]) -> u64 {
        let mut hash = band_idx as u64;
        for &val in chunk {
            hash = hash.wrapping_mul(31).wrapping_add(val);
        }
        hash
    }

    /// Get the total number of entries across all buckets.
    pub fn total_entries(&self) -> usize {
        self.buckets.values().map(|v| v.len()).sum()
    }

    /// Get the number of unique buckets.
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    /// Clear all buckets.
    pub fn clear(&mut self) {
        self.buckets.clear();
    }
}

/// MinHash signature generator for function features.
#[derive(Debug, Clone)]
pub struct MinHashSignature {
    /// Number of hash functions.
    pub num_hashes: usize,
    /// Hash function parameters (a, b pairs for h(x) = (a*x + b) mod p).
    pub hash_params: Vec<(u64, u64)>,
    /// Prime modulus.
    pub prime: u64,
}

impl MinHashSignature {
    /// Create a new MinHash signature generator.
    pub fn new(num_hashes: usize) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let prime = 2_u64.pow(61) - 1; // Mersenne prime
        let mut hash_params = Vec::with_capacity(num_hashes);
        for i in 0..num_hashes {
            let mut h1 = DefaultHasher::new();
            i.hash(&mut h1);
            let a = h1.finish() % prime;
            let mut h2 = DefaultHasher::new();
            (i + 1000).hash(&mut h2);
            let b = h2.finish() % prime;
            hash_params.push((a.max(1), b));
        }
        Self { num_hashes, hash_params, prime }
    }

    /// Compute the MinHash signature for a set of features.
    pub fn compute(&self, features: &[u64]) -> Vec<u64> {
        let mut signature = vec![u64::MAX; self.num_hashes];
        for &feature in features {
            for (i, &(a, b)) in self.hash_params.iter().enumerate() {
                let hash = (a.wrapping_mul(feature).wrapping_add(b)) % self.prime;
                signature[i] = signature[i].min(hash);
            }
        }
        signature
    }

    /// Compute the Jaccard similarity estimate between two signatures.
    pub fn jaccard_estimate(sig1: &[u64], sig2: &[u64]) -> f64 {
        if sig1.len() != sig2.len() || sig1.is_empty() {
            return 0.0;
        }
        let matches = sig1.iter().zip(sig2.iter()).filter(|(a, b)| a == b).count();
        matches as f64 / sig1.len() as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lsh_exception() {
        let e = LSHException::new("test error");
        assert_eq!(e.message(), "test error");
        assert!(format!("{}", e).contains("test error"));
    }

    #[test]
    fn test_lsh_hash_table_insert_query() {
        let mut table = LshHashTable::new(4, 2);
        table.insert(0, &[1, 2, 3, 4, 5, 6, 7, 8]);
        table.insert(1, &[1, 2, 3, 4, 9, 10, 11, 12]);
        assert_eq!(table.total_entries(), 8);

        // Query with exact same signature should find function 0
        let candidates = table.query(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(candidates.contains(&0));
    }

    #[test]
    fn test_lsh_hash_table_bucket_count() {
        let mut table = LshHashTable::new(2, 2);
        table.insert(0, &[1, 2, 3, 4]);
        table.insert(1, &[5, 6, 7, 8]);
        // With different signatures, there should be some unique buckets
        assert!(table.bucket_count() > 0);
    }

    #[test]
    fn test_minhash_signature() {
        let mh = MinHashSignature::new(128);
        let features1 = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let features2 = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let features3 = vec![9, 10, 11, 12, 13, 14, 15, 16];

        let sig1 = mh.compute(&features1);
        let sig2 = mh.compute(&features2);
        let sig3 = mh.compute(&features3);

        // Same features should produce identical signatures
        assert_eq!(sig1, sig2);
        // Different features should produce different signatures
        assert_ne!(sig1, sig3);
    }

    #[test]
    fn test_minhash_jaccard_estimate_identical() {
        let sig = vec![1, 2, 3, 4, 5];
        let est = MinHashSignature::jaccard_estimate(&sig, &sig);
        assert!((est - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_minhash_jaccard_estimate_different() {
        let sig1 = vec![1, 2, 3, 4, 5];
        let sig2 = vec![6, 7, 8, 9, 10];
        let est = MinHashSignature::jaccard_estimate(&sig1, &sig2);
        assert!((est - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_minhash_jaccard_estimate_empty() {
        let est = MinHashSignature::jaccard_estimate(&[], &[]);
        assert!((est - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_minhash_jaccard_estimate_partial() {
        let sig1 = vec![1, 2, 3, 4, 5];
        let sig2 = vec![1, 2, 9, 4, 10];
        let est = MinHashSignature::jaccard_estimate(&sig1, &sig2);
        assert!((est - 0.6).abs() < f64::EPSILON);
    }

    #[test]
    fn test_lsh_hash_table_clear() {
        let mut table = LshHashTable::new(4, 2);
        table.insert(0, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(table.total_entries() > 0);
        table.clear();
        assert_eq!(table.total_entries(), 0);
        assert_eq!(table.bucket_count(), 0);
    }
}
