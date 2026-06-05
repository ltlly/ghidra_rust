//! Utilities for Elasticsearch BSim queries.
//!
//! Ports `ghidra.features.bsim.query.elastic.ElasticUtilities`.

use std::collections::HashMap;
use serde_json::{json, Value as JsonValue};

/// Build an Elasticsearch query body for a BSim function search.
pub fn build_similarity_query(
    vector: &[f32],
    index: &str,
    num_results: usize,
) -> JsonValue {
    json!({
        "size": num_results,
        "query": {
            "function_score": {
                "query": { "match_all": {} },
                "script_score": {
                    "script": {
                        "source": "cosineSimilarity(params.query_vector, 'signature') + 1.0",
                        "params": {
                            "query_vector": vector
                        }
                    }
                }
            }
        },
        "_source": ["function_name", "exe_name", "address"]
    })
}

/// Build an Elasticsearch filter clause from BSim filter atoms.
pub fn build_filter_clause(filters: &[(&str, &str)]) -> JsonValue {
    let clauses: Vec<JsonValue> = filters.iter()
        .map(|(field, value)| {
            json!({ "term": { *field: *value } })
        })
        .collect();
    json!({ "bool": { "must": clauses } })
}

/// Parse Elasticsearch search hits into a result map.
pub fn parse_hits(hits: &JsonValue) -> Vec<HashMap<String, String>> {
    let mut results = Vec::new();
    if let Some(hits_array) = hits["hits"]["hits"].as_array() {
        for hit in hits_array {
            let mut row = HashMap::new();
            if let Some(source) = hit["_source"].as_object() {
                for (key, val) in source {
                    row.insert(key.clone(), val.to_string());
                }
            }
            if let Some(score) = hit["_score"].as_f64() {
                row.insert("_score".to_string(), score.to_string());
            }
            results.push(row);
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_similarity_query() {
        let vec = vec![0.1, 0.2, 0.3];
        let q = build_similarity_query(&vec, "bsim_index", 10);
        assert!(q["size"].as_u64().unwrap() == 10);
        assert!(q["query"]["function_score"].is_object());
    }

    #[test]
    fn test_build_filter_clause() {
        let filters = vec![("architecture", "x86"), ("compiler", "gcc")];
        let clause = build_filter_clause(&filters);
        let must = clause["bool"]["must"].as_array().unwrap();
        assert_eq!(must.len(), 2);
    }
}
