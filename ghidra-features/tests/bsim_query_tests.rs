//! Tests for BSim query infrastructure ported from Ghidra's Java Features/BSim package.
//!
//! Covers: server config, protocol types, description management,
//! client database abstractions, file database, scoring, and GUI filters.

use ghidra_features::bsim::{
    query, description, gui, client,
};

// ============================================================================
// ServerConfig and BSimServerInfo
// ============================================================================

#[test]
fn test_server_config_creation() {
    let config = query::ServerConfig::new("localhost", 5432, client::ConnectionType::Postgresql)
        .with_database("bsim")
        .with_username("user")
        .with_password("pass")
        .with_ssl(true);

    assert_eq!(config.hostname, "localhost");
    assert_eq!(config.port, 5432);
    assert_eq!(config.database_name, "bsim");
    assert!(config.use_ssl);
    assert_eq!(config.url(), "localhost:5432");
}

#[test]
fn test_bsim_server_info() {
    let config = query::ServerConfig::new("localhost", 9200, client::ConnectionType::Elasticsearch);
    let info = query::BSimServerInfo::new(config);
    assert!(!info.reachable);
    assert!(info.version.is_none());
}

// ============================================================================
// GenSignatures
// ============================================================================

#[test]
fn test_gen_signatures_add_executable() {
    let mut gen = query::GenSignatures::new();
    let idx = gen.add_executable("abc", "prog", "gcc", "x86");
    assert_eq!(idx, 0);
}

#[test]
fn test_gen_signatures_add_function_with_signature() {
    use ghidra_features::bsim::FeatureVector;
    let mut gen = query::GenSignatures::new();
    gen.add_executable("abc", "prog", "gcc", "x86");
    let fv = FeatureVector::from_pairs(vec![1, 2, 3], vec![1.0, 1.0, 1.0]);
    gen.add_function_with_signature(0, "main", Some(0x1000), fv);
    assert_eq!(gen.signed_function_count(), 1);
}

// ============================================================================
// DecompileFunctionTask and ParallelDecompileTask
// ============================================================================

#[test]
fn test_decompile_function_task() {
    let mut task = query::DecompileFunctionTask::new("main", 0x1000, 0);
    assert!(!task.completed);
    task.complete();
    assert!(task.completed);
}

#[test]
fn test_parallel_decompile_task() {
    let mut task = query::ParallelDecompileTask::new();
    assert_eq!(task.total_count(), 0);
    task.add_task(query::DecompileFunctionTask::new("a", 0x1000, 0));
    task.add_task(query::DecompileFunctionTask::new("b", 0x2000, 0));
    assert_eq!(task.total_count(), 2);
}

// ============================================================================
// Protocol types
// ============================================================================

#[test]
fn test_bsim_query() {
    use description::FunctionDescription;
    let q = query::protocol::BSimQuery::new(FunctionDescription::new(0, "main", Some(0x1000)))
        .with_max_results(50)
        .with_min_similarity(0.9);
    assert_eq!(q.max_results, 50);
    assert_eq!(q.min_similarity, 0.9);
}

#[test]
fn test_bsim_filter() {
    use query::protocol::{BSimFilter, FilterAtom, FilterOperator};
    let mut filter = BSimFilter::new();
    assert!(filter.is_empty());
    filter.add_atom(FilterAtom::new("arch", FilterOperator::Equals, "x86"));
    assert_eq!(filter.num_atoms(), 1);
    filter.set_flag_filter(0xFF, 0x01);
    assert_eq!(filter.flags_mask(), 0xFF);
}

#[test]
fn test_query_nearest() {
    use query::protocol::QueryNearest;
    use description::FunctionDescription;
    let mut q = QueryNearest::new();
    assert_eq!(q.thresh, QueryNearest::DEFAULT_SIMILARITY_THRESHOLD);
    q.add_function(FunctionDescription::new(0, "test", Some(0x1000)));
    assert_eq!(q.functions.len(), 1);
}

#[test]
fn test_exe_specifier() {
    use query::protocol::ExeSpecifier;
    let spec = ExeSpecifier::new("libc.so", "x86:LE:64:default", "abc123");
    assert_eq!(spec.name, "libc.so");
}

#[test]
fn test_insert_request() {
    use query::protocol::{InsertRequest, ExeSpecifier, FunctionEntry};
    let spec = ExeSpecifier::new("test", "x86", "md5");
    let mut req = InsertRequest::new(spec);
    req.add_function(FunctionEntry::new("f1", 0x100, "h1"));
    assert_eq!(req.function_count(), 1);
}

#[test]
fn test_pair_input_and_note() {
    use query::protocol::{PairInput, PairNote};
    let pair = PairInput::new("a", "b", "m1", "m2", 0x100, 0x200);
    let note = PairNote::new(pair, 0.85, 0.9);
    assert!(note.matched);
    assert_eq!(note.similarity, 0.85);
}

#[test]
fn test_response_types() {
    use query::protocol::*;
    use description::ExecutableRecord;

    // ResponseName
    let mut r = ResponseName::new();
    r.add_executable(ExecutableRecord::new("abc", "test", "x86", "gcc"));
    assert_eq!(r.total, 1);

    // ResponseDelete
    let r = ResponseDelete::new(true, 5);
    assert!(r.success);

    // ResponseError
    let r = ResponseError::new(404, "not found").as_recoverable();
    assert!(r.recoverable);

    // ResponseInsert
    let r = ResponseInsert::success(10);
    assert!(r.success);

    // ResponseCluster
    let mut r = ResponseCluster::new();
    r.add_cluster(ClusterNote::new(1));
    assert_eq!(r.total, 1);
}

#[test]
fn test_staging_manager() {
    use query::protocol::StagingManager;
    use description::FunctionDescription;
    let mut sm = StagingManager::new(3);
    sm.stage_function(FunctionDescription::new(0, "f1", Some(0x1000)));
    sm.stage_function(FunctionDescription::new(0, "f2", Some(0x2000)));
    assert!(!sm.is_ready());
    sm.stage_function(FunctionDescription::new(0, "f3", Some(0x3000)));
    assert!(is_ready(&sm));
    assert_eq!(sm.staged_count(), 3);
}

fn is_ready(sm: &ghidra_features::bsim::query::protocol::StagingManager) -> bool {
    sm.is_ready()
}

// ============================================================================
// Description types
// ============================================================================

#[test]
fn test_function_description() {
    use description::FunctionDescription;
    let func = FunctionDescription::new(0, "main", Some(0x1000));
    assert_eq!(func.function_name, "main");
    assert_eq!(func.address, Some(0x1000));
}

#[test]
fn test_executable_record() {
    use description::ExecutableRecord;
    let exe = ExecutableRecord::new("abc123", "test", "x86", "gcc");
    assert_eq!(exe.md5, "abc123");
    assert_eq!(exe.executable_name, "test");
}

#[test]
fn test_database_information() {
    use description::DatabaseInformation;
    let mut info = DatabaseInformation::default();
    info.database_name = "test_db".to_string();
    assert_eq!(info.database_name, "test_db");
}

// ============================================================================
// Client database abstractions
// ============================================================================

#[test]
fn test_jdbc_data_source() {
    use query::client::BSimJDBCDataSource;
    let ds = BSimJDBCDataSource::new("jdbc:postgresql://localhost/bsim", "admin")
        .with_property("ssl", "true");
    assert_eq!(ds.url, "jdbc:postgresql://localhost/bsim");
    assert_eq!(ds.properties.get("ssl"), Some(&"true".to_string()));
}

#[test]
fn test_connection_manager() {
    use query::client::BSimPostgresDBConnectionManager;
    let mut mgr = BSimPostgresDBConnectionManager::new("localhost:5432", 5);
    assert!(mgr.acquire());
    assert_eq!(mgr.active_connections(), 1);
    mgr.release();
    assert_eq!(mgr.active_connections(), 0);
}

#[test]
fn test_connection_manager_pool_limit() {
    use query::client::BSimPostgresDBConnectionManager;
    let mut mgr = BSimPostgresDBConnectionManager::new("localhost", 2);
    assert!(mgr.acquire());
    assert!(mgr.acquire());
    assert!(!mgr.acquire());
}

// ============================================================================
// File database (H2)
// ============================================================================

#[test]
fn test_h2_file_function_database() {
    use query::file::H2FileFunctionDatabase;
    use query::client::AbstractSQLFunctionDatabase;
    use description::FunctionDescription;

    let mut db = H2FileFunctionDatabase::new("/tmp/test.bsim");
    let func = FunctionDescription::new(0, "main", Some(0x1000));
    db.insert_function(&func).unwrap();
    assert_eq!(db.function_count(), 1);

    let found = db.query_by_name(0, "main");
    assert!(found.is_some());
}

#[test]
fn test_vector_store() {
    use query::file::{VectorStore, VectorStoreEntry};
    let mut store = VectorStore::new("/tmp/vectors");
    store.add_entry(VectorStoreEntry::new("f1", 0));
    store.add_entry(VectorStoreEntry::new("f2", 1));
    assert_eq!(store.len(), 2);
    assert!(store.find("f1", 0).is_some());
}

#[test]
fn test_h2_vector_table() {
    use query::file::H2VectorTable;
    let mut table = H2VectorTable::new("test_vectors");
    table.insert(0, "main", vec![1.0, 2.0, 3.0]);
    assert_eq!(table.len(), 1);
    let vec = table.get(0, "main").unwrap();
    assert_eq!(vec.len(), 3);
}

#[test]
fn test_h2_connection_manager() {
    use query::file::BSimH2FileDBConnectionManager;
    let mut mgr = BSimH2FileDBConnectionManager::new(5);
    assert_eq!(mgr.active_connections(), 0);
    let _db = mgr.get_connection("/tmp/test1.bsim");
    assert_eq!(mgr.active_connections(), 1);
    assert!(mgr.close_connection("/tmp/test1.bsim"));
    assert_eq!(mgr.active_connections(), 0);
}

#[test]
fn test_vector_store_manager() {
    use query::file::BSimVectorStoreManager;
    let mut mgr = BSimVectorStoreManager::new("/tmp/bsim");
    assert_eq!(mgr.store_count(), 0);
    let _store = mgr.get_store("db1");
    assert_eq!(mgr.store_count(), 1);
    assert!(mgr.remove_store("db1"));
    assert_eq!(mgr.store_count(), 0);
}

// ============================================================================
// Scoring
// ============================================================================

#[test]
fn test_table_score_caching() {
    use query::client::scoring::{TableScoreCaching, ScoreCaching};
    let mut cache = TableScoreCaching::new(0.5, 0.7);
    cache.commit_self_score("abc123", 42.0);
    assert_eq!(cache.get_self_score("abc123"), Some(42.0));
    assert_eq!(cache.get_self_score("not_found"), None);
}

#[test]
fn test_temporary_score_caching() {
    use query::client::scoring::{TemporaryScoreCaching, ScoreCaching};
    let mut cache = TemporaryScoreCaching::new(0.3, 0.5);
    cache.commit_self_score("md5test", 99.5);
    assert_eq!(cache.get_self_score("md5test"), Some(99.5));
}

#[test]
fn test_file_score_caching_roundtrip() {
    use query::client::scoring::{FileScoreCaching, ScoreCaching};
    let mut cache = FileScoreCaching::new("/tmp/scores.dat", 0.5, 0.7);
    cache.commit_self_score("aaa111", 10.0);
    cache.commit_self_score("bbb222", 20.0);
    let data = cache.serialize();
    let restored = FileScoreCaching::deserialize(&data);
    assert_eq!(restored.get_self_score("aaa111"), Some(10.0));
    assert_eq!(restored.get_self_score("bbb222"), Some(20.0));
}

#[test]
fn test_executable_scorer() {
    use query::client::scoring::{ExecutableScorer, FunctionPair};
    let mut scorer = ExecutableScorer::new(0.5);
    scorer.add_function_pair(FunctionPair::new(
        "f1".into(), 0x1000, 0,
        "f2".into(), 0x2000, 1,
        0.8, 0.9,
    ));
    assert_eq!(scorer.pair_count(), 1);
}

#[test]
fn test_id_histogram() {
    use query::client::scoring::IdHistogram;
    let ids = vec![100, 200, 100, 300, 200, 100, 0];
    let hist = IdHistogram::build_from_ids(ids.into_iter());
    let hist_vec: Vec<_> = hist.iter().collect();
    assert_eq!(hist_vec.len(), 3); // 0 is skipped
}

// ============================================================================
// GUI filter types
// ============================================================================

#[test]
fn test_bsim_filter_type() {
    use gui::filters::{BSimFilterType, FilterField, FilterOperator, FilterValue};
    let filter = BSimFilterType {
        name: "Architecture".to_string(),
        field: FilterField::Architecture,
        operator: FilterOperator::Equals,
        value: FilterValue::String("x86".to_string()),
        negated: false,
    };
    assert_eq!(filter.name, "Architecture");
    assert!(!filter.negated);
}

#[test]
fn test_bsim_search_settings() {
    let s = gui::BSimSearchSettings::default();
    assert_eq!(s.min_similarity, 0.7);
    assert_eq!(s.max_results, 100);
    assert!(s.search_all_executables);
}

#[test]
fn test_bsim_match_result() {
    let r = gui::BSimMatchResult {
        query_hash: [0u8; 32],
        matched_function_name: "malloc".to_string(),
        matched_address: "0x1000".to_string(),
        similarity: 0.95,
        confidence: 0.85,
        status: gui::BSimResultStatus::Pending,
    };
    assert_eq!(r.status, gui::BSimResultStatus::Pending);
}

#[test]
fn test_bsim_overview_row() {
    let row = gui::BSimOverviewRow {
        name: "libc.so".to_string(),
        architecture: "x86:LE:64:default".to_string(),
        compiler: "gcc".to_string(),
        function_count: 1500,
        md5: "abc123".to_string(),
        date_added: "2024-01-01".to_string(),
    };
    assert_eq!(row.function_count, 1500);
}

// ============================================================================
// Protocol serialization roundtrip
// ============================================================================

#[test]
fn test_protocol_serialization_roundtrip() {
    use query::protocol::QueryNearest;
    let q = QueryNearest::new();
    let json = serde_json::to_string(&q).unwrap();
    let _: QueryNearest = serde_json::from_str(&json).unwrap();
}

// ============================================================================
// Description significance
// ============================================================================

#[test]
fn test_description_significance() {
    use ghidra_features::bsim::query::description::description_significance::*;
    let config = SignificanceConfig::default();
    assert!(config.feature_weight > 0.0);
}

// ============================================================================
// LSHException
// ============================================================================

#[test]
fn test_lsh_exception() {
    let e = query::LshException::new("vector mismatch");
    assert!(format!("{}", e).contains("vector mismatch"));
}
