//! Integration tests for newly ported BSim modules.
//!
//! Tests the protocol types, filter types, and value editors that were
//! ported from Ghidra's Java BSim feature.

use ghidra_bsim::query::additional_protocol::*;
use ghidra_bsim::query::protocol::ExeSpecifier;

#[test]
fn test_bsim_query_type_variants() {
    let types = [
        BSimQueryType::Nearest,
        BSimQueryType::Name,
        BSimQueryType::Pair,
        BSimQueryType::Children,
        BSimQueryType::Cluster,
        BSimQueryType::Info,
        BSimQueryType::Delete,
        BSimQueryType::ExeCount,
        BSimQueryType::ExeInfo,
        BSimQueryType::NearestVector,
        BSimQueryType::VectorId,
        BSimQueryType::VectorMatch,
        BSimQueryType::OptionalExist,
        BSimQueryType::OptionalValues,
        BSimQueryType::Update,
    ];
    assert_eq!(types.len(), 15);
    // All should be distinct
    for i in 0..types.len() {
        for j in (i + 1)..types.len() {
            assert_ne!(types[i], types[j]);
        }
    }
}

#[test]
fn test_cluster_note_serialization() {
    let cn = ClusterNote {
        function_name: "func_a".into(),
        cluster_id: 7,
        confidence: 0.88,
        note: Some("close match".into()),
    };
    let json = serde_json::to_string(&cn).unwrap();
    let back: ClusterNote = serde_json::from_str(&json).unwrap();
    assert_eq!(back.cluster_id, 7);
    assert_eq!(back.note.as_deref(), Some("close match"));
}

#[test]
fn test_similarity_result_fields() {
    let sr = SimilarityResult {
        function_name: "main".into(),
        executable_name: "prog.exe".into(),
        score: 0.92,
        metric: "cosine".into(),
        md5: Some("abc123def456".into()),
        address: Some("0x401000".into()),
    };
    assert_eq!(sr.score, 0.92);
    assert_eq!(sr.metric, "cosine");
    assert!(sr.md5.is_some());
}

#[test]
fn test_similarity_vector_result_vector_length() {
    let svr = SimilarityVectorResult {
        function_name: "func".into(),
        score: 0.5,
        vector: (0..100).map(|i| i as f64 * 0.01).collect(),
        executable_name: Some("test.exe".into()),
    };
    assert_eq!(svr.vector.len(), 100);
    assert!((svr.vector[0] - 0.0).abs() < 1e-10);
    assert!((svr.vector[99] - 0.99).abs() < 1e-10);
}

#[test]
fn test_function_entry_complete() {
    let fe = FunctionEntry {
        name: "calculate_sum".into(),
        address: "0x401000".into(),
        size: 128,
        executable_name: Some("math.exe".into()),
        vector: Some(vec![0.1; 64]),
        tags: vec!["utility".into(), "math".into()],
    };
    assert_eq!(fe.tags.len(), 2);
    assert!(fe.vector.as_ref().unwrap().len() == 64);
}

#[test]
fn test_function_staging_manager_operations() {
    let mut sm = StagingManagerState::new(5);

    for i in 0..5 {
        sm.add_batch(FunctionStaging {
            entries: vec![FunctionEntry {
                name: format!("func_{}", i),
                address: format!("0x{:x}", 0x1000 + i * 0x10),
                size: 16,
                executable_name: None,
                vector: None,
                tags: vec![],
            }],
            executable_name: "test.exe".into(),
            batch_id: format!("batch_{}", i),
        });
    }
    assert!(sm.is_full());
    assert_eq!(sm.total_staged, 5);

    let flushed = sm.flush();
    assert_eq!(flushed.len(), 5);
    assert!(!sm.is_full());
    assert_eq!(sm.total_staged, 0);
}

#[test]
fn test_executable_result_with_deduping() {
    let er = ExecutableResultWithDeDuping {
        name: "libcrypto.so".into(),
        function_count: 500,
        unique_count: 380,
        md5: Some("deadbeef".into()),
        architecture: Some("x86_64".into()),
    };
    // Dedup should reduce count
    assert!(er.unique_count < er.function_count);
    // Serialization
    let json = serde_json::to_string(&er).unwrap();
    let back: ExecutableResultWithDeDuping = serde_json::from_str(&json).unwrap();
    assert_eq!(back.unique_count, 380);
}

#[test]
fn test_insert_request_with_functions() {
    let ir = InsertRequest {
        exe: ExeSpecifier::new("test.exe"),
        entries: vec![
            FunctionEntry {
                name: "main".into(),
                address: "0x401000".into(),
                size: 64,
                executable_name: Some("test.exe".into()),
                vector: None,
                tags: vec![],
            },
            FunctionEntry {
                name: "helper".into(),
                address: "0x401040".into(),
                size: 32,
                executable_name: Some("test.exe".into()),
                vector: None,
                tags: vec!["internal".into()],
            },
        ],
        overwrite: true,
    };
    assert_eq!(ir.entries.len(), 2);
    assert!(ir.overwrite);
    let json = serde_json::to_string(&ir).unwrap();
    assert!(json.contains("main"));
}

#[test]
fn test_password_change_serialization() {
    let pc = PasswordChange {
        database: "bsim_db".into(),
        old_password: "oldpass".into(),
        new_password: "newpass123".into(),
    };
    let json = serde_json::to_string(&pc).unwrap();
    let back: PasswordChange = serde_json::from_str(&json).unwrap();
    assert_eq!(back.database, "bsim_db");
}

#[test]
fn test_response_types() {
    let r1 = ResponseNearest {
        results: vec![
            SimilarityResult {
                function_name: "f1".into(),
                executable_name: "e1".into(),
                score: 0.85,
                metric: "cosine".into(),
                md5: None,
                address: None,
            },
            SimilarityResult {
                function_name: "f2".into(),
                executable_name: "e2".into(),
                score: 0.72,
                metric: "cosine".into(),
                md5: None,
                address: None,
            },
        ],
    };
    assert_eq!(r1.results.len(), 2);
    assert!(r1.results[0].score > r1.results[1].score);

    let r2 = ResponsePrewarm {
        success: true,
        pages_loaded: 512,
    };
    assert!(r2.success);
    assert_eq!(r2.pages_loaded, 512);
}

#[test]
fn test_similarity_note_roundtrip() {
    let sn = SimilarityNote {
        function_name: "target_func".into(),
        similarity: 0.97,
        details: vec![
            ("match_type".into(), "exact".into()),
            ("block_count".into(), "12".into()),
        ],
    };
    let json = serde_json::to_string(&sn).unwrap();
    let back: SimilarityNote = serde_json::from_str(&json).unwrap();
    assert_eq!(back.details.len(), 2);
    assert_eq!(back.details[0].0, "match_type");
}
