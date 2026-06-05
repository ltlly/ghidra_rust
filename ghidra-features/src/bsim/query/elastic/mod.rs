//! Elasticsearch-based BSim backend.
//!
//! Port of `ghidra.features.bsim.query.elastic`:
//! - [`ElasticDatabase`]: Elasticsearch BSim function database
//! - [`ElasticEffects`]: side effects for Elastic operations

use serde::{Deserialize, Serialize};

use super::super::description::{ExecutableRecord, FunctionDescription};

// New modules ported from Ghidra's BSim elastic package
pub mod base64_lite;
pub mod elastic_utilities;

/// Elasticsearch-backed BSim function database.
#[derive(Debug, Clone)]
pub struct ElasticDatabase {
    /// Elasticsearch host URL.
    pub host: String,
    /// Index name.
    pub index: String,
    /// Whether the index exists.
    index_exists: bool,
}

impl ElasticDatabase {
    /// Create a new Elastic database handle.
    pub fn new(host: impl Into<String>, index: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            index: index.into(),
            index_exists: false,
        }
    }

    /// Whether the index exists.
    pub fn index_exists(&self) -> bool {
        self.index_exists
    }

    /// Set whether the index exists.
    pub fn set_index_exists(&mut self, exists: bool) {
        self.index_exists = exists;
    }

    /// Get the full index URL.
    pub fn index_url(&self) -> String {
        format!("{}/{}", self.host, self.index)
    }
}

/// Side effects for Elasticsearch BSim operations.
#[derive(Debug, Clone, Default)]
pub struct ElasticEffects {
    /// Number of documents indexed.
    pub indexed_count: usize,
    /// Number of documents deleted.
    pub deleted_count: usize,
    /// Number of query requests made.
    pub query_count: usize,
}

impl ElasticEffects {
    /// Create a new empty effects tracker.
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elastic_database() {
        let db = ElasticDatabase::new("http://localhost:9200", "bsim");
        assert_eq!(db.index_url(), "http://localhost:9200/bsim");
        assert!(!db.index_exists());
    }

    #[test]
    fn test_elastic_effects() {
        let mut fx = ElasticEffects::new();
        fx.indexed_count = 100;
        assert_eq!(fx.indexed_count, 100);
    }
}
