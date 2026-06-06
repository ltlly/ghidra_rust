//! A signature record containing an LSH vector for function matching.
//!
//! Ports Ghidra's `ghidra.features.bsim.query.description.SignatureRecord`.

/// A signature record that associates a function's LSH (Locality-Sensitive Hash)
/// vector with a database vector ID and a count of duplicates.
#[derive(Debug, Clone)]
pub struct SignatureRecord {
    /// The LSH signature vector components.
    pub vector: Vec<u32>,
    /// The database vector ID.
    vector_id: u64,
    /// Number of duplicates of this signature within the database.
    count: i32,
}

impl SignatureRecord {
    /// Create a new signature record with the given vector.
    pub fn new(vector: Vec<u32>) -> Self {
        Self {
            vector,
            vector_id: 0,
            count: 0,
        }
    }

    /// Create a signature record with a pre-assigned vector ID.
    pub fn with_id(vector: Vec<u32>, vector_id: u64) -> Self {
        Self {
            vector,
            vector_id,
            count: 0,
        }
    }

    /// Set the database vector ID.
    pub fn set_vector_id(&mut self, id: u64) {
        self.vector_id = id;
    }

    /// Set the duplicate count.
    pub fn set_count(&mut self, count: i32) {
        self.count = count;
    }

    /// Get the LSH signature vector.
    pub fn vector(&self) -> &[u32] {
        &self.vector
    }

    /// Get the database vector ID.
    pub fn vector_id(&self) -> u64 {
        self.vector_id
    }

    /// Get the number of duplicates of this signature in the database.
    pub fn count(&self) -> i32 {
        self.count
    }
}

impl Default for SignatureRecord {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl PartialEq for SignatureRecord {
    fn eq(&self, other: &Self) -> bool {
        self.vector == other.vector
    }
}

impl Eq for SignatureRecord {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let s = SignatureRecord::new(vec![1, 2, 3]);
        assert_eq!(s.vector(), &[1, 2, 3]);
        assert_eq!(s.vector_id(), 0);
        assert_eq!(s.count(), 0);
    }

    #[test]
    fn test_with_id() {
        let s = SignatureRecord::with_id(vec![10, 20], 42);
        assert_eq!(s.vector_id(), 42);
    }

    #[test]
    fn test_setters() {
        let mut s = SignatureRecord::new(vec![1]);
        s.set_vector_id(99);
        s.set_count(5);
        assert_eq!(s.vector_id(), 99);
        assert_eq!(s.count(), 5);
    }

    #[test]
    fn test_equality() {
        let a = SignatureRecord::new(vec![1, 2, 3]);
        let b = SignatureRecord::new(vec![1, 2, 3]);
        let c = SignatureRecord::new(vec![1, 2, 4]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_default() {
        let s = SignatureRecord::default();
        assert!(s.vector().is_empty());
    }
}
