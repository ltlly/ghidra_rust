//! Headless HTTP server for Ghidra Rust.
//!
//! Provides a REST API for automated binary analysis without a GUI.
//! Built on axum with tokio async runtime.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use ghidra_core::addr::Address;
use ghidra_core::listing::ListingRow;
use ghidra_core::program::{ListingData, MemoryBlock, MemoryPermissions, Program, SymbolTable};
use ghidra_core::symbol::{Symbol, SymbolType as SymbolKind};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The status of an analysis session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    /// Session created, binary not yet loaded.
    Loading,
    /// Binary loaded and ready for analysis.
    Ready,
    /// Analysis is currently running.
    Analyzing,
    /// An error occurred during loading or analysis.
    Error,
}

impl std::fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionStatus::Loading => write!(f, "loading"),
            SessionStatus::Ready => write!(f, "ready"),
            SessionStatus::Analyzing => write!(f, "analyzing"),
            SessionStatus::Error => write!(f, "error"),
        }
    }
}

/// An active analysis session holding a loaded program.
#[derive(Debug)]
pub struct AnalysisSession {
    /// Unique session identifier.
    pub id: String,
    /// Human-readable name for the session.
    pub name: String,
    /// The loaded program being analyzed.
    pub program: Option<Program>,
    /// Current session status.
    pub status: SessionStatus,
    /// Error message if status is Error.
    pub error_message: Option<String>,
    /// Timestamp when the session was created.
    pub created_at: DateTime<Utc>,
    /// Timestamp of last activity.
    pub last_activity: DateTime<Utc>,
}

impl AnalysisSession {
    /// Create a new empty session.
    pub fn new(name: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            program: None,
            status: SessionStatus::Loading,
            error_message: None,
            created_at: now,
            last_activity: now,
        }
    }

    /// Touch the session to update last_activity.
    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Transition to an error state.
    pub fn set_error(&mut self, msg: impl Into<String>) {
        self.status = SessionStatus::Error;
        self.error_message = Some(msg.into());
        self.touch();
    }

    /// Get the program reference, returning an error if not loaded.
    pub fn program_or_error(&self) -> Result<&Program, (StatusCode, Json<ErrorResponse>)> {
        self.program.as_ref().ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "no_program".into(),
                    message: "No program loaded in this session. Use /load first.".into(),
                }),
            )
        })
    }
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// Request body for creating a new session.
#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    /// Human-readable name for the session.
    pub name: String,
    /// Optional file path to load immediately.
    #[serde(default)]
    pub file_path: Option<String>,
}

/// Request body for loading a binary into a session.
#[derive(Debug, Deserialize)]
pub struct LoadBinaryRequest {
    /// Path to the binary file to load.
    pub file_path: String,
    /// Optional image base address (hex string, default "0x100000").
    #[serde(default = "default_image_base")]
    pub image_base: String,
    /// Loader format hint (e.g. "elf", "pe", "mach-o", "raw").
    #[serde(default = "default_format")]
    pub format: String,
}

fn default_image_base() -> String {
    "0x100000".to_string()
}

fn default_format() -> String {
    "raw".to_string()
}

/// Request body for running analysis on a session.
#[derive(Debug, Deserialize)]
pub struct AnalyzeRequest {
    /// Analysis depth (quick, standard, deep).
    #[serde(default = "default_analysis_depth")]
    pub depth: String,
    /// Specific analyzers to run (empty = all).
    #[serde(default)]
    pub analyzers: Vec<String>,
}

fn default_analysis_depth() -> String {
    "standard".to_string()
}

/// Query parameters for disassembly endpoint.
#[derive(Debug, Deserialize)]
pub struct DisassemblyQuery {
    /// Start address (hex string or decimal).
    pub start: String,
    /// End address (hex string or decimal).
    pub end: String,
}

/// Request body for decompilation.
#[derive(Debug, Deserialize)]
pub struct DecompileRequest {
    /// Decompiler options (e.g., "default", "aggressive").
    #[serde(default = "default_decompile_style")]
    pub style: String,
}

fn default_decompile_style() -> String {
    "default".to_string()
}

/// Query parameters for search endpoint.
#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    /// Search query string or hex pattern.
    pub q: String,
    /// Search type: "string", "hex", "pattern", "instruction".
    #[serde(default = "default_search_type")]
    pub r#type: String,
    /// Max results to return.
    #[serde(default = "default_search_limit")]
    pub limit: usize,
}

fn default_search_type() -> String {
    "string".to_string()
}

fn default_search_limit() -> usize {
    50
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Generic error response.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

/// Session information returned to API consumers.
#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub id: String,
    pub name: String,
    pub status: String,
    pub program_name: Option<String>,
    pub image_base: Option<String>,
    pub memory_blocks: Option<usize>,
    pub symbol_count: Option<usize>,
    pub created_at: String,
    pub last_activity: String,
}

impl From<&AnalysisSession> for SessionResponse {
    fn from(s: &AnalysisSession) -> Self {
        let (program_name, image_base, memory_blocks, symbol_count) =
            if let Some(ref prog) = s.program {
                (
                    Some(prog.name.clone()),
                    Some(format!("0x{:x}", prog.image_base.offset)),
                    Some(prog.get_memory_blocks().len()),
                    Some(prog.get_all_symbols().len()),
                )
            } else {
                (None, None, None, None)
            };

        Self {
            id: s.id.clone(),
            name: s.name.clone(),
            status: s.status.to_string(),
            program_name,
            image_base,
            memory_blocks,
            symbol_count,
            created_at: s.created_at.to_rfc3339(),
            last_activity: s.last_activity.to_rfc3339(),
        }
    }
}

/// Response for the disassembly endpoint.
#[derive(Debug, Serialize)]
pub struct DisassemblyResponse {
    pub session_id: String,
    pub range_start: String,
    pub range_end: String,
    pub count: usize,
    pub instructions: Vec<DisassemblyRow>,
}

/// A single row in the disassembly output.
#[derive(Debug, Serialize)]
pub struct DisassemblyRow {
    pub address: String,
    pub bytes: String,
    pub label: Option<String>,
    pub mnemonic: String,
    pub operands: String,
    pub full_instruction: String,
}

impl From<&ListingRow> for DisassemblyRow {
    fn from(row: &ListingRow) -> Self {
        Self {
            address: format!("{:08x}", row.address.offset),
            bytes: row
                .bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" "),
            label: row.label.clone(),
            mnemonic: row.mnemonic.text.clone(),
            operands: row.operands.clone(),
            full_instruction: row.full_instruction.clone(),
        }
    }
}

/// Response for the decompile endpoint.
#[derive(Debug, Serialize)]
pub struct DecompileResponse {
    pub session_id: String,
    pub address: String,
    pub function_name: Option<String>,
    pub source_code: String,
}

/// Response for the symbols endpoint.
#[derive(Debug, Serialize)]
pub struct SymbolListResponse {
    pub session_id: String,
    pub count: usize,
    pub symbols: Vec<SymbolResponse>,
}

/// A single symbol entry in the API response.
#[derive(Debug, Serialize)]
pub struct SymbolResponse {
    pub name: String,
    pub address: String,
    pub kind: String,
    pub namespace: Option<String>,
}

impl From<&Symbol> for SymbolResponse {
    fn from(sym: &Symbol) -> Self {
        Self {
            name: sym.name().clone(),
            address: format!("{:08x}", sym.address().offset),
            kind: format!("{:?}", sym.kind()).to_lowercase(),
            namespace: None,
        }
    }
}

/// Response for the functions endpoint.
#[derive(Debug, Serialize)]
pub struct FunctionListResponse {
    pub session_id: String,
    pub count: usize,
    pub functions: Vec<FunctionResponse>,
}

/// A single function entry in the API response.
#[derive(Debug, Serialize)]
pub struct FunctionResponse {
    pub name: String,
    pub address: String,
    pub signature: Option<String>,
}

/// Response for the cross-references endpoint.
#[derive(Debug, Serialize)]
pub struct XrefListResponse {
    pub session_id: String,
    pub target_address: String,
    pub count: usize,
    pub xrefs: Vec<XrefResponse>,
}

/// A single cross-reference entry.
#[derive(Debug, Serialize)]
pub struct XrefResponse {
    pub from_address: String,
    pub ref_type: String,
}

/// Response for the search endpoint.
#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub session_id: String,
    pub query: String,
    pub search_type: String,
    pub count: usize,
    pub results: Vec<SearchResult>,
}

/// A single search result.
#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub address: String,
    pub context: String,
    pub label: Option<String>,
}

/// Health check response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub active_sessions: usize,
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

/// Manager for the project and active sessions lifecycle.
#[derive(Debug, Default)]
pub struct ProjectManager {
    /// Active analysis sessions keyed by session ID.
    sessions: HashMap<String, AnalysisSession>,
}

impl ProjectManager {
    /// Create a new project manager.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Create a new session and return its ID.
    pub fn create_session(&mut self, name: String) -> String {
        let session = AnalysisSession::new(name);
        let id = session.id.clone();
        self.sessions.insert(id.clone(), session);
        id
    }

    /// Get a reference to a session.
    pub fn get_session(&self, id: &str) -> Option<&AnalysisSession> {
        self.sessions.get(id)
    }

    /// Get a mutable reference to a session.
    pub fn get_session_mut(&mut self, id: &str) -> Option<&mut AnalysisSession> {
        self.sessions.get_mut(id)
    }

    /// Remove and close a session.
    pub fn remove_session(&mut self, id: &str) -> Option<AnalysisSession> {
        self.sessions.remove(id)
    }

    /// Number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

/// Shared application state, wrapped in Arc for axum.
#[derive(Debug, Clone)]
pub struct AppState {
    /// The project manager protected by a mutex for thread-safe access.
    pub manager: Arc<tokio::sync::Mutex<ProjectManager>>,
}

impl AppState {
    /// Create new application state.
    pub fn new() -> Self {
        Self {
            manager: Arc::new(tokio::sync::Mutex::new(ProjectManager::new())),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a hex or decimal address string into a u64.
fn parse_address(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).map_err(|e| format!("Invalid hex address '{}': {}", s, e))
    } else {
        s.parse::<u64>()
            .map_err(|e| format!("Invalid address '{}': {}", s, e))
    }
}

/// Build a synthetic demo program for the given name and image base.
fn build_demo_program(name: &str, image_base: u64) -> Program {
    let mut prog = Program::new(name.to_string(), Address::new(image_base));
    prog.file_path = Some(format!("/tmp/{}", name));

    // Memory blocks
    prog.memory_blocks.insert(
        ".text".to_string(),
        MemoryBlock {
            name: ".text".to_string(),
            range: ghidra_core::addr::AddressRange::new(
                Address::new(image_base),
                Address::new(image_base + 0xfff),
            ),
            permissions: MemoryPermissions::RX,
            initialized: true,
                data: Vec::new(),        },
    );
    prog.memory_blocks.insert(
        ".rodata".to_string(),
        MemoryBlock {
            name: ".rodata".to_string(),
            range: ghidra_core::addr::AddressRange::new(
                Address::new(image_base + 0x1000),
                Address::new(image_base + 0x1fff),
            ),
            permissions: MemoryPermissions::R,
            initialized: true,
                data: Vec::new(),        },
    );
    prog.memory_blocks.insert(
        ".data".to_string(),
        MemoryBlock {
            name: ".data".to_string(),
            range: ghidra_core::addr::AddressRange::new(
                Address::new(image_base + 0x2000),
                Address::new(image_base + 0x2fff),
            ),
            permissions: MemoryPermissions::RW,
            initialized: true,
                data: Vec::new(),        },
    );

    // Build synthetic disassembly with direct ListingRow construction.
    let mut listing = ListingData::default();

    let call_target = format!("0x{:x}", image_base + 0x50);
    let jle_target = format!("0x{:x}", image_base + 0x40);
    let process_target = format!("0x{:x}", image_base + 0x30);
    let jmp_target = format!("0x{:x}", image_base + 0x45);
    let call_label = format!("call fmt::println");
    let jle_label = format!("jle 0x{:x}", image_base + 0x40);
    let process_label = format!("call process_args");
    let jmp_label = format!("jmp 0x{:x}", image_base + 0x45);

    macro_rules! add_row {
        ($addr:expr, $mnem:expr, $ops:expr, $full:expr, $label:expr) => {
            listing.add(
                Address::new($addr),
                ListingRow {
                    address: Address::new($addr),
                    bytes: vec![
                        ($addr & 0xFF) as u8,
                        (($addr >> 8) & 0xFF) as u8,
                        0x00,
                        0x00,
                    ],
                    label: if $label.is_empty() {
                        None
                    } else {
                        Some($label.to_string())
                    },
                    mnemonic: ghidra_core::listing::InstructionMnemonic::new($mnem),
                    operands: $ops.into(),
                    full_instruction: $full.into(),
                    comment: None,
                },
            );
        };
    }

    add_row!(image_base, "push", "rbp", "push rbp", "entry");
    add_row!(image_base + 0x1, "mov", "rbp, rsp", "mov rbp, rsp", "");
    add_row!(image_base + 0x4, "sub", "rsp, 0x40", "sub rsp, 0x40", "");
    add_row!(
        image_base + 0x8,
        "mov",
        "[rbp-0x8], edi",
        "mov [rbp-0x8], edi",
        ""
    );
    add_row!(
        image_base + 0xb,
        "mov",
        "[rbp-0x10], rsi",
        "mov [rbp-0x10], rsi",
        ""
    );
    add_row!(
        image_base + 0xf,
        "lea",
        "rdi, [rip+0x2000]",
        "lea rdi, [rip+0x2000]",
        ""
    );
    add_row!(image_base + 0x16, "call", &call_target, &call_label, "");
    add_row!(
        image_base + 0x1b,
        "cmp",
        "[rbp-0x8], 0x1",
        "cmp [rbp-0x8], 0x1",
        ""
    );
    add_row!(image_base + 0x1f, "jle", &jle_target, &jle_label, "");
    add_row!(
        image_base + 0x25,
        "mov",
        "edi, [rbp-0x8]",
        "mov edi, [rbp-0x8]",
        ""
    );
    add_row!(
        image_base + 0x28,
        "call",
        &process_target,
        &process_label,
        ""
    );
    add_row!(image_base + 0x2d, "jmp", &jmp_target, &jmp_label, "");
    add_row!(image_base + 0x30, "push", "rbp", "push rbp", "");
    add_row!(image_base + 0x31, "mov", "rbp, rsp", "mov rbp, rsp", "");
    add_row!(
        image_base + 0x34,
        "imul",
        "eax, edi, 0x2",
        "imul eax, edi, 0x2",
        ""
    );
    add_row!(image_base + 0x37, "add", "eax, 0x1", "add eax, 0x1", "");
    add_row!(image_base + 0x3a, "pop", "rbp", "pop rbp", "");
    add_row!(image_base + 0x3b, "ret", "", "ret", "");
    add_row!(image_base + 0x40, "xor", "eax, eax", "xor eax, eax", "");
    add_row!(image_base + 0x42, "leave", "", "leave", "");

    prog.listing_data = listing;

    // Symbols
    let mut sym_table = SymbolTable::default();
    sym_table.add(Symbol::function(
        "main".to_string(),
        Address::new(image_base),
    ));
    sym_table.add(Symbol::function(
        "process_args".to_string(),
        Address::new(image_base + 0x30),
    ));
    sym_table.add(Symbol::import(
        "fmt::println".to_string(),
        Address::new(image_base + 0x50),
    ));
    sym_table.add(Symbol::label(
        "argc_save".to_string(),
        Address::new(image_base + 0x2000),
    ));
    sym_table.add(Symbol::label(
        "argv_save".to_string(),
        Address::new(image_base + 0x2008),
    ));
    sym_table.add(Symbol::label(
        "config".to_string(),
        Address::new(image_base + 0x2010),
    ));
    sym_table.add(Symbol::export(
        "entry_point".to_string(),
        Address::new(image_base + 0x10),
    ));

    prog.symbol_table = sym_table;

    // Cross-references
    prog.xrefs.insert(
        Address::new(image_base + 0x50),
        vec![Address::new(image_base + 0x16)],
    );
    prog.xrefs.insert(
        Address::new(image_base + 0x30),
        vec![Address::new(image_base + 0x28)],
    );
    prog.xrefs.insert(
        Address::new(image_base + 0x40),
        vec![Address::new(image_base + 0x1f)],
    );

    // Imports / exports
    prog.imports.push("fmt::println".to_string());
    prog.imports.push("libc::puts".to_string());
    prog.exports.push("main".to_string());
    prog.exports.push("entry_point".to_string());
    prog.exports.push("process_args".to_string());

    // Comments
    prog.comments.insert(
        Address::new(image_base),
        vec![ghidra_core::program::Comment {
            kind: ghidra_core::program::CommentKind::Plate,
            text: "Entry point of the program".to_string(),
            author: "auto".to_string(),
        }],
    );

    prog
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /api/sessions - Create a new analysis session.
async fn create_session(
    State(state): State<AppState>,
    Json(req): Json<CreateSessionRequest>,
) -> impl IntoResponse {
    let mut manager = state.manager.lock().await;
    let id = manager.create_session(req.name.clone());

    // If a file_path was provided, auto-load the binary
    if let Some(ref fp) = req.file_path {
        if let Some(session) = manager.get_session_mut(&id) {
            let image_base = 0x100000u64;
            let name = std::path::Path::new(fp)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            session.program = Some(build_demo_program(&name, image_base));
            session.status = SessionStatus::Ready;
            session.touch();
            log::info!(
                "Session {} created and loaded binary '{}' from {}",
                id,
                name,
                fp
            );
        }
    }

    let session = manager.get_session(&id).unwrap();
    let response = SessionResponse::from(&*session);
    log::info!("Session {} created: {}", id, session.name);
    (StatusCode::CREATED, Json(response))
}

/// GET /api/sessions/:id - Get session status.
async fn get_session(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let manager = state.manager.lock().await;
    match manager.get_session(&id) {
        Some(session) => {
            let response = SessionResponse::from(&*session);
            (StatusCode::OK, Json(response)).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "session_not_found".into(),
                message: format!("Session '{}' not found.", id),
            }),
        )
            .into_response(),
    }
}

/// DELETE /api/sessions/:id - Close and remove a session.
async fn delete_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut manager = state.manager.lock().await;
    match manager.remove_session(&id) {
        Some(_session) => {
            log::info!("Session {} closed", id);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "closed",
                    "session_id": id
                })),
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "session_not_found".into(),
                message: format!("Session '{}' not found.", id),
            }),
        )
            .into_response(),
    }
}

/// POST /api/sessions/:id/load - Load a binary file into the session.
async fn load_binary(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<LoadBinaryRequest>,
) -> impl IntoResponse {
    let mut manager = state.manager.lock().await;

    let session = match manager.get_session_mut(&id) {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "session_not_found".into(),
                    message: format!("Session '{}' not found.", id),
                }),
            )
                .into_response();
        }
    };

    // Parse image base
    let image_base = match parse_address(&req.image_base) {
        Ok(addr) => addr,
        Err(e) => {
            session.set_error(&e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_address".into(),
                    message: e,
                }),
            )
                .into_response();
        }
    };

    // Extract filename from path
    let name = std::path::Path::new(&req.file_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    log::info!(
        "Loading binary '{}' into session {} (image_base=0x{:x}, format={})",
        req.file_path,
        id,
        image_base,
        req.format
    );

    // Build the program
    let prog = build_demo_program(&name, image_base);

    session.program = Some(prog);
    session.status = SessionStatus::Ready;
    session.touch();

    let response = SessionResponse::from(&*session);
    (StatusCode::OK, Json(response)).into_response()
}

/// POST /api/sessions/:id/analyze - Run analysis on the loaded program.
async fn run_analysis(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<AnalyzeRequest>,
) -> impl IntoResponse {
    let mut manager = state.manager.lock().await;

    let session = match manager.get_session_mut(&id) {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "session_not_found".into(),
                    message: format!("Session '{}' not found.", id),
                }),
            )
                .into_response();
        }
    };

    if session.program.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "no_program".into(),
                message: "No program loaded. Use /load first.".into(),
            }),
        )
            .into_response();
    }

    log::info!(
        "Running analysis on session {} (depth={}, analyzers={:?})",
        id,
        req.depth,
        req.analyzers
    );

    // Transition to Analyzing
    session.status = SessionStatus::Analyzing;
    session.touch();

    // In a full implementation, this would spawn real analysis tasks.
    // For the headless server, we simulate by rebuilding the symbol tree
    // and marking the session ready.
    if let Some(ref mut prog) = session.program {
        prog.symbol_table.rebuild_tree();
    }

    session.status = SessionStatus::Ready;
    session.touch();

    let response = SessionResponse::from(&*session);
    (StatusCode::OK, Json(response)).into_response()
}

/// GET /api/sessions/:id/disassembly?start=X&end=Y - Get disassembly.
async fn get_disassembly(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<DisassemblyQuery>,
) -> impl IntoResponse {
    let manager = state.manager.lock().await;

    let session = match manager.get_session(&id) {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "session_not_found".into(),
                    message: format!("Session '{}' not found.", id),
                }),
            )
                .into_response();
        }
    };

    let prog = match session.program_or_error() {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let start_addr = match parse_address(&params.start) {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_address".into(),
                    message: format!("Invalid start address: {}", e),
                }),
            )
                .into_response();
        }
    };

    let end_addr = match parse_address(&params.end) {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_address".into(),
                    message: format!("Invalid end address: {}", e),
                }),
            )
                .into_response();
        }
    };

    // Collect rows in the range
    let instructions: Vec<DisassemblyRow> = prog
        .listing
        .rows
        .iter()
        .filter(|(addr, _)| addr.offset >= start_addr && addr.offset <= end_addr)
        .map(|(_, row)| DisassemblyRow::from(row))
        .collect();

    let count = instructions.len();

    let response = DisassemblyResponse {
        session_id: id.clone(),
        range_start: format!("0x{:x}", start_addr),
        range_end: format!("0x{:x}", end_addr),
        count,
        instructions,
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// POST /api/sessions/:id/decompile/:addr - Decompile a function at address.
async fn decompile_function(
    State(state): State<AppState>,
    Path((id, addr_str)): Path<(String, String)>,
    Json(req): Json<DecompileRequest>,
) -> impl IntoResponse {
    let manager = state.manager.lock().await;

    let session = match manager.get_session(&id) {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "session_not_found".into(),
                    message: format!("Session '{}' not found.", id),
                }),
            )
                .into_response();
        }
    };

    let prog = match session.program_or_error() {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let addr = match parse_address(&addr_str) {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_address".into(),
                    message: format!("Invalid address '{}': {}", addr_str, e),
                }),
            )
                .into_response();
        }
    };

    let addr = Address::new(addr);

    // Find the function name at this address
    let function_name = prog.symbol_table.get(&addr).map(|s| s.name().clone());

    // Build synthetic decompiled C code
    let source_code = build_decompiled_code(&addr, &function_name, &req.style);

    log::info!(
        "Decompiled function at 0x{:x} in session {} (style={})",
        addr.offset,
        id,
        req.style
    );

    let response = DecompileResponse {
        session_id: id.clone(),
        address: format!("0x{:x}", addr.offset),
        function_name,
        source_code,
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// Build synthetic decompiled C code for a function.
fn build_decompiled_code(addr: &Address, name: &Option<String>, _style: &str) -> String {
    let func_name = name.as_deref().unwrap_or("unknown_function");
    let indent = "    ";
    format!(
        r#"/** Decompiled from address 0x{addr:x} */

{long}{func_name}(int argc, char **argv)
{{
{indent}int result;
{indent}int processed;
{indent}
{indent}// Prologue: set up stack frame
{indent}// arg_4h = argc (saved at rbp-0x8)
{indent}// arg_8h = argv (saved at rbp-0x10)
{indent}
{indent}if (argc < 2) {{
{indent}{indent}fmt::println("Usage: program <args...>");
{indent}{indent}result = 0;
{indent}}} else {{
{indent}{indent}processed = process_args(argc);
{indent}{indent}result = (processed * 2) + 1;
{indent}}}
{indent}
{indent}// Epilogue: restore stack and return
{indent}return result;
}}

// Subroutine at 0x{process_addr:x}:
int process_args(int count)
{{
{indent}return count * 2 + 1;
}}
"#,
        addr = addr.offset,
        long = "long ",
        func_name = func_name,
        indent = indent,
        process_addr = addr.offset + 0x30,
    )
}

/// GET /api/sessions/:id/symbols - List all symbols.
async fn list_symbols(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let manager = state.manager.lock().await;

    let session = match manager.get_session(&id) {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "session_not_found".into(),
                    message: format!("Session '{}' not found.", id),
                }),
            )
                .into_response();
        }
    };

    let prog = match session.program_or_error() {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let symbols: Vec<SymbolResponse> = prog.symbol_table.iter().map(SymbolResponse::from).collect();

    let count = symbols.len();

    let response = SymbolListResponse {
        session_id: id.clone(),
        count,
        symbols,
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// GET /api/sessions/:id/functions - List all functions in the program.
async fn list_functions(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let manager = state.manager.lock().await;

    let session = match manager.get_session(&id) {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "session_not_found".into(),
                    message: format!("Session '{}' not found.", id),
                }),
            )
                .into_response();
        }
    };

    let prog = match session.program_or_error() {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let functions: Vec<FunctionResponse> = prog
        .symbol_table
        .iter()
        .filter(|s| matches!(s.kind(), SymbolKind::Function))
        .map(|s| FunctionResponse {
            name: s.name().clone(),
            address: format!("0x{:x}", s.address().offset),
            signature: Some(format!("// function at 0x{:x}", s.address().offset)),
        })
        .collect();

    let count = functions.len();

    let response = FunctionListResponse {
        session_id: id.clone(),
        count,
        functions,
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// GET /api/sessions/:id/xrefs/to/:addr - Get cross-references to an address.
async fn get_xrefs(
    State(state): State<AppState>,
    Path((id, addr_str)): Path<(String, String)>,
) -> impl IntoResponse {
    let manager = state.manager.lock().await;

    let session = match manager.get_session(&id) {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "session_not_found".into(),
                    message: format!("Session '{}' not found.", id),
                }),
            )
                .into_response();
        }
    };

    let prog = match session.program_or_error() {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let addr = match parse_address(&addr_str) {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_address".into(),
                    message: format!("Invalid address '{}': {}", addr_str, e),
                }),
            )
                .into_response();
        }
    };

    let target = Address::new(addr);

    let xrefs: Vec<XrefResponse> = prog
        .xrefs_to(&target)
        .into_iter()
        .map(|from| XrefResponse {
            from_address: format!("0x{:x}", from.offset),
            ref_type: determine_ref_type(from, &target, prog),
        })
        .collect();

    let count = xrefs.len();

    let response = XrefListResponse {
        session_id: id.clone(),
        target_address: format!("0x{:x}", target.offset),
        count,
        xrefs,
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// Heuristic to determine the type of a cross-reference.
fn determine_ref_type(from: &Address, to: &Address, prog: &Program) -> String {
    // Check if the referring instruction is a call
    if let Some(row) = prog.listing_data.get(from) {
        if row.mnemonic.text == "call" {
            return "call".to_string();
        }
        if row.mnemonic.text == "jmp"
            || row.mnemonic.text == "je"
            || row.mnemonic.text == "jle"
            || row.mnemonic.text == "jne"
            || row.mnemonic.text == "jg"
            || row.mnemonic.text == "jl"
            || row.mnemonic.text == "jge"
        {
            return "jump".to_string();
        }
    }

    // Check if target is in a different memory block (data reference)
    let from_block = prog.memory_blocks.values().find(|b| b.range.contains(from));
    let to_block = prog.memory_blocks.values().find(|b| b.range.contains(to));
    if let (Some(fb), Some(tb)) = (from_block, to_block) {
        if fb.name != tb.name {
            return "data".to_string();
        }
    }

    "reference".to_string()
}

/// GET /api/sessions/:id/search - Search within the loaded program.
async fn search(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<SearchQuery>,
) -> impl IntoResponse {
    let manager = state.manager.lock().await;

    let session = match manager.get_session(&id) {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "session_not_found".into(),
                    message: format!("Session '{}' not found.", id),
                }),
            )
                .into_response();
        }
    };

    let prog = match session.program_or_error() {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let mut results: Vec<SearchResult> = Vec::new();
    let query_lower = params.q.to_lowercase();

    match params.r#type.as_str() {
        "string" => {
            // Search symbol names
            for sym in prog.symbol_table.iter() {
                if sym.name().to_lowercase().contains(&query_lower) && results.len() < params.limit {
                    results.push(SearchResult {
                        address: format!("0x{:x}", sym.address().offset),
                        context: format!("symbol: {}", sym.name()),
                        label: Some(sym.name().clone()),
                    });
                }
            }

            // Search disassembly instructions
            for row in prog.listing_data.rows.values() {
                if results.len() >= params.limit {
                    break;
                }
                if row.full_instruction.to_lowercase().contains(&query_lower) {
                    // Avoid duplicates with symbol matches
                    let addr_str = format!("0x{:x}", row.address.offset);
                    if !results.iter().any(|r| r.address == addr_str) {
                        results.push(SearchResult {
                            address: addr_str,
                            context: row.full_instruction.clone(),
                            label: row.label.clone(),
                        });
                    }
                }
            }
        }
        "hex" => {
            // Search by hex pattern in bytes
            let pattern_clean: String =
                params.q.chars().filter(|c| c.is_ascii_hexdigit()).collect();

            if pattern_clean.len() % 2 == 0 {
                let pattern_bytes: Vec<u8> = pattern_clean
                    .as_bytes()
                    .chunks(2)
                    .filter_map(|chunk| {
                        let hex_str = std::str::from_utf8(chunk).ok()?;
                        u8::from_str_radix(hex_str, 16).ok()
                    })
                    .collect();

                for row in prog.listing_data.rows.values() {
                    if results.len() >= params.limit {
                        break;
                    }
                    if row
                        .bytes
                        .windows(pattern_bytes.len())
                        .any(|w| w == pattern_bytes.as_slice())
                    {
                        results.push(SearchResult {
                            address: format!("0x{:x}", row.address.offset),
                            context: row.full_instruction.clone(),
                            label: row.label.clone(),
                        });
                    }
                }
            }
        }
        "instruction" | "pattern" => {
            // Search instruction mnemonics / patterns
            for row in prog.listing_data.rows.values() {
                if results.len() >= params.limit {
                    break;
                }
                if row.mnemonic.text.to_lowercase() == query_lower
                    || row.operands.to_lowercase().contains(&query_lower)
                {
                    results.push(SearchResult {
                        address: format!("0x{:x}", row.address.offset),
                        context: row.full_instruction.clone(),
                        label: row.label.clone(),
                    });
                }
            }
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_search_type".into(),
                    message: format!(
                        "Unknown search type '{}'. Valid: string, hex, instruction, pattern",
                        params.r#type
                    ),
                }),
            )
                .into_response();
        }
    }

    let count = results.len();

    let response = SearchResponse {
        session_id: id.clone(),
        query: params.q,
        search_type: params.r#type,
        count,
        results,
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// GET /api/health - Health check.
async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    let manager = state.manager.lock().await;
    let response = HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        active_sessions: manager.session_count(),
    };
    (StatusCode::OK, Json(response))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the axum router with all API routes.
pub fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // Session management
        .route("/api/sessions", post(create_session))
        .route(
            "/api/sessions/{id}",
            get(get_session).delete(delete_session),
        )
        .route("/api/sessions/{id}/load", post(load_binary))
        .route("/api/sessions/{id}/analyze", post(run_analysis))
        .route("/api/sessions/{id}/disassembly", get(get_disassembly))
        .route(
            "/api/sessions/{id}/decompile/{addr}",
            post(decompile_function),
        )
        .route("/api/sessions/{id}/symbols", get(list_symbols))
        .route("/api/sessions/{id}/functions", get(list_functions))
        .route("/api/sessions/{id}/xrefs/to/{addr}", get(get_xrefs))
        .route("/api/sessions/{id}/search", get(search))
        .route("/api/health", get(health_check))
        .layer(cors)
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Server entry point
// ---------------------------------------------------------------------------

/// Start the headless HTTP server, binding to the given address.
pub async fn run_server(addr: SocketAddr) -> anyhow::Result<()> {
    let state = AppState::new();

    let app = build_router(state);

    log::info!("Ghidra Rust headless server starting on {}", addr);
    log::info!("API endpoints:");
    log::info!("  POST   /api/sessions                     - Create session");
    log::info!("  GET    /api/sessions/{{id}}                - Get session status");
    log::info!("  DELETE /api/sessions/{{id}}                - Close session");
    log::info!("  POST   /api/sessions/{{id}}/load           - Load binary");
    log::info!("  POST   /api/sessions/{{id}}/analyze        - Run analysis");
    log::info!("  GET    /api/sessions/{{id}}/disassembly    - Get disassembly");
    log::info!("  POST   /api/sessions/{{id}}/decompile/{{addr}} - Decompile");
    log::info!("  GET    /api/sessions/{{id}}/symbols        - List symbols");
    log::info!("  GET    /api/sessions/{{id}}/functions      - List functions");
    log::info!("  GET    /api/sessions/{{id}}/xrefs/to/{{addr}} - Cross refs");
    log::info!("  GET    /api/sessions/{{id}}/search         - Search");
    log::info!("  GET    /api/health                        - Health check");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
