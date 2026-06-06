//! Ghidra BSim -- Binary Similarity feature.
//!
//! Ports Ghidra's `Features/BSim` Java package into Rust.  Provides:
//!
//! - **Query engine** ([`query`]): `FunctionDatabase` trait and implementations
//!   for PostgreSQL, Elasticsearch, and file-based backends.
//! - **Client** ([`query::client`]): `BSimClientFactory` and connection management.
//! - **Description types** ([`query::description`]): Function signatures,
//!   executable descriptions, and similarity metrics.
//! - **Protocol** ([`query::protocol`]): Wire-format types for BSim RPC.
//! - **Ingest** ([`query::ingest`]): Signature ingestion pipeline.
//! - **Facade** ([`query::facade`]): High-level convenience API.
//! - **GUI** ([`gui`]): Filters, overview, and search dialogs.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────┐
//! │            FunctionDatabase (trait)           │
//! │  Core query interface for BSim backends       │
//! └──────────────────────────────────────────────┘
//!     │             │              │
//!     ▼             ▼              ▼
//! ┌─────────┐  ┌──────────┐  ┌─────────┐
//! │PostgreSQL│  │Elastic   │  │  File   │
//! │ Backend  │  │Backend   │  │ Backend │
//! └─────────┘  └──────────┘  └─────────┘
//! ```

pub mod query;
pub mod gui;

// Re-export key types
pub use query::description::{
    BSimExecutableInfo, BSimFunctionDescription, BSimResultSet,
    CallgraphEntry, CategoryRecord, DatabaseInformation, DescriptionManager,
    FunctionDescriptionMapper, FunctionSignatureInfo, RowKey,
    SignatureRecord, SimilarityMetric, VectorResult,
};
pub use query::server_config::ServerConfig;
pub use query::bsim_server_info::BSimServerInfo;
pub use query::function_database::FunctionDatabase;
pub use query::lsh::LSHException;
pub use query::client_sql::{
    CancelledSqlException, Configuration as BSimConfiguration, CosineScorer,
    ExecutableComparison, ExecutableScorer, EuclideanScorer, FileScoreCache, IdHistogram,
    IdSqlResolution, NoDatabaseException, RowKeySql, ScoreCache, SqlEffects, TableScoreCache,
    TemporaryScoreCache,
};
pub use query::protocol::{
    AdjustVectorIndexRequest, BSimFilter, BSimRequest, BSimResponse,
    ChildAtom, ClusterNoteData, CreateDatabaseRequest, DatabaseInfoData,
    DropDatabaseRequest, ExeResultData, ExeSpecifier, FilterAtom,
    FilterAtomEntry, FilterType, FunctionEntryData, InsertOptionalValues,
    InsertRequestData, NullStaging, PairInputData, PairNoteData,
    PasswordChangeRequest, PreFilter, QueryChildren, QueryCluster,
    QueryDelete, QueryInfo, QueryInfoData, QueryName, QueryNearest,
    QueryPair, QueryResponseRecord, ResponseNearest, SimilarityNoteData,
    StagingManager, VectorResultData,
};
pub use gui::results::{
    BSimApplyAction, BSimApplyResult, BSimMatchResult, BSimOverviewRowObject,
    BSimResultStatus, BSimSearchSettings, FunctionComparisonException,
};
pub use query::error_info::{
    BSimHTMLGenerator, BSimServerInformation, BSimSettings, ErrorCode, ErrorInfo,
};
// Additional protocol types
pub use query::additional_protocol::{
    InstallCategoryRequest, InstallMetadataRequest, InstallTagRequest,
    PrewarmRequest, QueryExeCount, QueryExeInfo, QueryNearestVector,
    QueryOptionalExist, QueryOptionalValues, QueryUpdate, QueryVectorId,
    QueryVectorMatch, ResponseAdjustIndex, ResponseChildren, ResponseCluster,
    ResponseDelete, ResponseDropDatabase, ResponseError, ResponseExe,
    ResponseInfo, ResponseInsert, ResponseName, ResponseNearestVector,
    ResponseOptionalExist, ResponseOptionalValues, ResponsePassword,
    ResponsePrewarm, ResponseUpdate, ResponseVectorId, ResponseVectorMatch,
    SimilarityResult, SimilarityVectorResult, ExecutableResultWithDeDuping,
    FunctionStaging,
};
// File backend types
pub use query::file::{
    FileFunctionDatabase, H2FileDBConnectionManager, H2VectorTable,
    VectorStore, VectorStoreEntry, VectorStoreManager,
};
// Elastic backend types
pub use query::elastic::{
    Base64VectorFactory, ElasticConnection, ElasticEffects,
    ElasticFunctionDatabase, ElasticIdResolution, RowKeyElastic,
};
